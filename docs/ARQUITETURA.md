# Arquitetura do OpenNT

Como o código do OpenNT está organizado. A árvore segue a do kernel do
Windows NT: cada componente do executive (Ke, Mm, Io, Ob, Ps, Se, Ex, Cm,
Rtl...) mora na sua pasta e é dono do próprio código e das rotinas que
exporta; a HAL, os drivers e a inicialização ficam separados, como no NT.

## 1. Crates

| Crate | Papel |
| --- | --- |
| `boot` | setor de boot e stage2 em `global_asm!` (modo real → protegido → 64 bits) |
| `kernel` | binário `no_std` ligado na VA de sistema 0xFFFFF800_40001000 por `kernel/link.ld` (código PIC, executável estático) e empacotado pelo `xtask` como PE32+ de base fixa 0xFFFFF800_40000000 |
| `xtask` | build, PE do kernel, imagem de disco, volume NTFS, QEMU, `test-boot`, `test-all`, `capturas`, `status` e o cliente de texto do depurador do kernel (`debug`) |
| `tools/opennt-kd` | o cliente do depurador do kernel, só com a biblioteca padrão: protocolo remoto do GDB, símbolos (`kernel.elf`, exports dos PEs, PDBs públicos com cache e download), pilha pela `.pdata` e pelos frame pointers, tipos do PDB do ntoskrnl, expressões, breakpoints, rastro de instruções e os comandos de texto; usado pelo `xtask` e pelo `opennt-dbg` |
| `tools/opennt-dbg` | `opennt-dbg`, o depurador gráfico (egui/eframe, painéis do `egui_dock`, desmontagem do iced-x86, linhas e variáveis do DWARF pelo `addr2line`/`gimli`); as dependências dele não entram no build do kernel nem do `xtask` |
| `tools/opennt-re` | `opennt-re`, o depurador de engenharia reversa (layout no estilo dos depuradores de engenharia reversa) para o kernel e os processos de usuário, sobre o mesmo cliente; as dependências dele também ficam fora do kernel e do `xtask` |
| `tools/opennt-mcp` | `opennt-mcp`, o servidor do Model Context Protocol para agentes de IA (JSON-RPC 2.0 por stdio ou HTTP local), sobre o mesmo cliente; também a desmontagem e a análise automática que o `opennt-re` usa |

## 2. Árvore do kernel

```
kernel/src/
├── main.rs            entrada (kernel_main), BSS, panic_handler
├── hal/               HAL: portas, serial, CPU, memória física, LAPIC, RTC, heap,
│   │                  ACPI (tabelas e a tabela de energia do acpi.sys), PCI,
│   │                  firmware, o driver PnP da HAL, HalPrivateDispatchTable,
│   │                  HalDispatchTable (HaliQuerySystemInformation) e exports Hal*
│   ├── amd64/         código x64: interrupções, anel 3, trampolim dos APs, chamadas
│   │                  MS-ABI, trampolins dos exports, entradas privadas, serviços
│   └── x86bios/       interface x86 BIOS (x86Bios*): o BIOS de vídeo da máquina num
│                      processador de modo real emulado
├── rtl/               suporte do próprio kernel em Rust: debug_print!, SpinLock,
│                      KernelError, texto, tempo
├── nano/              IDT/PIC/timer, canais de IPC, registro de serviços
├── ntos/              o executive (o ntoskrnl)
│   ├── inc/           cabeçalhos: estruturas do NT geradas dos símbolos (types),
│   │                  acesso tipado (field), offsets legados (nt_abi) e NTSTATUS
│   ├── init/          boot em fases, configuração de build e a tabela de exports
│   ├── ke/            kernel: relógio, IRQL, DPCs, APCs, timers, despacho, SMP,
│   │                  bugcheck e a tabela de serviços (services)
│   ├── mm/            memória: pool, PFN, paginação, sysload (carga de imagens),
│   │   │              pe_loader, memória de convidado
│   │   └── section/   seções e visões (creasect/mapview/umapview)
│   ├── io/            I/O Manager, PnP, IRPs, ciclo de vida dos drivers
│   │   ├── file/      leitura, escrita, consulta, exclusão e serviços Zw de arquivo
│   │   └── completion/ portas de conclusão
│   ├── ob/            Object Manager: tabela de handles, namespace, callbacks
│   │   ├── objects/   tipos de objeto (driver, dispositivo, arquivo, seção...)
│   │   └── handles/   handles por tipo de objeto
│   ├── ps/            processos, threads, escalonador
│   │   ├── context/   contexto de thread (psctx)
│   │   ├── notify/    rotinas de notificação (psnotify)
│   │   ├── silo/      silos de servidor
│   │   └── user/      serviços Nt* chamados pelo modo usuário
│   ├── se/            segurança: descritores, ACLs, SIDs, SDDL, integridade de
│   │                  código e níveis de assinatura
│   │   ├── token/     tokens de acesso
│   │   └── capability/ capacidades e AppContainer
│   ├── ex/            executive: push locks, rundown, lookaside, callbacks, pool,
│   │                  hosts de extensão (ExRegisterHost/ExRegisterExtension)
│   │   ├── wnf/       Windows Notification Facility
│   │   └── license/   licenciamento
│   ├── cm/            Registry: namespace (registry), hives de arquivo (hive_list,
│   │   │              hive_file, hive_services), montagem das hives do boot
│   │   │              (hive_init), escritor preguiçoso (lazy_flush), tabelas
│   │   │              das hives de máquina (seed)
│   │   ├── hive/      formato regf: bloco base, bins e células, listas de
│   │   │              subchaves, 'sk', 'nk'/'vk'/'db', logs e descarga
│   │   ├── key/       chaves e serviços Nt/Zw de chave, blocos de notificação
│   │   │              de mudança por corpo de chave (notify)
│   │   └── service/   serviços e drivers (base, canal, RPC)
│   ├── rtl/           a Rtl do NT: strings, Unicode, páginas de código, AVL, árvore
│   │   │              rubro-negra (rb_tree), bitmap, exceções, imagens PE, tabelas de
│   │   │              átomos (atom), heap (heap), CRT (crt, printf, scanf)
│   │   └── resource/  recursos de imagens (ldrrsrc) e tabelas de mensagens
│   ├── alpc/          ALPC (connect/, message/, resource/)
│   ├── kd/            depurador do kernel: o estado que os drivers veem e o
│   │                  próprio depurador do OpenNT (protocolo remoto do GDB,
│   │                  consultas de objetos do NT, rastro de instruções)
│   ├── po/ etw/ dbgk/ fsrtl/
│   ├── pf/            prefetcher: os eventos \KernelObjects do Superfetch
│   ├── bcd/           biblioteca BCD do kernel: o BcdSyncMutant
│   ├── bgk/           console do vídeo de boot (Bgk*), fonte e tela de bugcheck
│   ├── inbv/          vídeo de boot: posse do vídeo entre kernel e driver
│   ├── ttm/           Terminal Topology Manager (notificações de dispositivo)
│   ├── em/            Errata Manager (provedores e regras do INF de errata)
│   └── test/          autotestes de boot (phase3.rs a phase7.rs, self_test.rs;
│                      multiprocess/, um módulo por assunto, chamado pela fase 7)
├── drivers/           drivers internos
│   ├── fs/            sistemas de arquivos: RAMFS de boot, volumes, NTFS
│   ├── bus/ storage/ input/ video/ console/
├── shell/             shell e `sc`
└── apps/              programas de exemplo `hello`/`pisca`
```

Os binários reais do Windows (hal.dll, ci.dll, cng.sys, drivers de teclado,
mouse e disco) são carregados do volume NTFS pelo `ntos/mm/sysload.rs` e pelo
`ntos/io/lifecycle.rs`; o OpenNT só implementa o que o `ntoskrnl.exe`
implementa.

## 3. Dentro de um componente

### 3.1 Onde mora o código de um export

No NT, uma rotina exportada é uma função comum, implementada no arquivo do
assunto dentro do componente: os byte-range locks ficam no arquivo de file
locks do FsRtl, as MDLs no de MDLs do Mm, o access check no de access check
do Se, as leituras do cache no de cópias do Cache Manager. Exportar é só pôr
o nome na lista de exports do kernel. Não existe um "arquivo de exports" onde
a lógica mora. O OpenNT segue o mesmo modelo, em três camadas:

| Camada | Onde | O que contém |
| --- | --- | --- |
| **Lógica** | `ntos/<componente>/<assunto>.rs` (ou uma subpasta do assunto) | a implementação: estruturas, estado, tabelas, algoritmos, validação, em funções Rust com tipos de verdade |
| **Adaptador** | `ntos/<componente>/exports.rs` | um `pub mod <grupo>` por grupo, com um handler curto por export e a `Group` |
| **Tabela** | `ntos/init/export_names.rs` e `ntos/init/exports.rs` | os nomes na ordem fixa dos ids e a lista de grupos (o papel da lista de exports do kernel no NT) |

Regras:

- **O `exports.rs` só adapta.** Cada handler lê os argumentos do `Call`, chama
  a função do assunto e converte o resultado (NTSTATUS, ponteiro, BOOLEAN):
  poucas linhas, sem `if` de semântica. No `exports.rs` **não** entram:
  `static`/estado, structs e enums, tabelas e constantes de layout, laços de
  algoritmo, funções auxiliares, nem validação de parâmetros. Se um grupo do
  `exports.rs` passa de algumas dezenas de linhas, a lógica está no lugar
  errado.
- **Por que existe adaptador.** No NT a assinatura em C já é a interface
  binária e o export aponta direto para a função. No OpenNT a chamada chega
  pelo trampolim como um `Call`; o adaptador é só essa ponte, e é a única
  diferença em relação ao NT.
- **Arquivo do assunto, com nome do assunto**, no estilo do NT:
  `fsrtl/file_lock.rs`, `fsrtl/oplock.rs`, `rtl/hash_table.rs`, `cc/copy.rs`,
  `mm/mdl.rs`, `se/access_check.rs`. Nunca um arquivo por export, nunca um
  arquivo ou grupo com nome de driver (`dxgkrnl_support.rs`,
  `watchdog-support`).
- **Componente certo.** O prefixo do export diz o dono: FsRtl* em `fsrtl`, Cc*
  em `cc`, Mm* em `mm`, Se* em `se`, Rtl* e a CRT em `rtl`. Um export de um
  componente não mora no `exports.rs` de outro.
- **Exports de dados** (`MmSystemRangeStart`, `PsJobType`...) seguem igual: a
  célula e o valor vêm do assunto; o `exports.rs` só lista o par
  `(nome, getter)` em `data_exports`.

Exemplo:

```rust
// ntos/fsrtl/file_lock.rs — a lógica (endereços do convidado como u64)
pub fn check_lock_for_read_access(file_lock: u64, irp: u64) -> bool { /* ... */ }

// ntos/fsrtl/exports.rs — o adaptador
fn check_lock_for_read_access(call: &Call) -> Result<u64, KernelError> {
    Ok(file_lock::check_lock_for_read_access(call.arg(1), call.arg(2)) as u64)
}
```

O autoteste da fase 6 chama o export pelo nome (`call_export`) e cobre as duas
camadas juntas. Testes só da lógica podem chamar a função do assunto direto.

### 3.2 Outras regras

- **Famílias.** Quando um assunto ocupa vários arquivos, eles ficam numa
  subpasta do componente (`ex/wnf/`, `mm/section/`, `se/token/`...), como os
  subdiretórios do NT. Arquivos pequenos do mesmo assunto podem dividir um
  arquivo (`pub mod x { ... }`), como em `io/small.rs`.
- **Nada de arquivo por export.** Uma rotina nova entra no arquivo do assunto
  dela; o export novo ganha só o adaptador no `exports.rs` do componente.
- **Cabeçalho.** Todo módulo começa com um `//!` que diz o papel e o contrato.

### 3.3 Acesso à memória e estruturas do NT

No NT, kernel e drivers dividem o espaço de endereçamento e o C usa as
estruturas direto: `Irp->IoStatus.Status = STATUS_SUCCESS;` é um `mov`, com o
layout dos cabeçalhos e checagem de tipo. O OpenNT faz o mesmo:

- **As estruturas vêm de `ntos/inc/types`**, geradas pelo `cargo xtask
  nt-types` a partir dos símbolos do ntoskrnl (`build/symbols/ntkrnlmp.pdb`,
  Windows 10 19041; ausente, o xtask o baixa do servidor público de símbolos
  pelo GUID/idade registrados e confere a identidade): o mesmo layout com
  que o kernel real foi compilado, `#[repr(C)]`, com `size_of`/`offset_of!`
  conferidos em compilação. Os nomes são os do NT em snake_case (`IoStatus` ->
  `io_status`, `Tail.Overlay.CurrentStackLocation` ->
  `tail.overlay.current_stack_location`; palavras reservadas ganham `_`, como
  `type_`). Membros que o C sobrepõe (uniões anônimas) ficam em vistas
  encadeadas por `Deref`, então o nome resolve direto (`thread.state`,
  `iosb.pointer`). O diretório é gerado e não se edita à mão: os tipos
  pedidos (raízes, que entram com o fecho do que contêm por valor; famílias;
  as provas de `nt_abi.rs`) ficam em `types/nt_types.toml`, e
  `cargo xtask nt-types --check` falha se algum arquivo gerado estiver
  desatualizado. Uma estrutura que consta dos símbolos entra como raiz no
  `nt_types.toml`, nunca à mão. As exceções são `types/wdk.rs` e os
  `types/extra_*.rs`, mantidos à mão no mesmo estilo só com o que os
  símbolos não têm (estruturas públicas do WDK/SDK, como OB_CALLBACK_*,
  classes de informação dos Nt* e atributos ALPC, e privadas lidas na
  desmontagem), cada uma citando a origem; os `extra_*.rs` também
  reexportam, nos caminhos já usados, as estruturas que passaram a ser
  geradas.
- **Estruturas próprias do OpenNT** (corpos de objeto, registros internos que
  não são layouts do NT) ficam privadas no componente dono, com a mesma
  receita: `#[repr(C)]` de `Field<T>`/`Reserved<N>`/structs do NT,
  `unsafe impl NtStruct` e asserções de `size_of`/`offset_of!` (exemplo no
  cabeçalho de `inc/field.rs`).
- **Acesso pelos campos** (`ntos/inc/field.rs`): cada folha escalar é um
  `Field<T>` na memória do próprio objeto; `get`/`set` são **um** acesso
  volátil da largura do campo, no endereço virtual, sem tradução por acesso.
  Ponteiros são `Field<u64>`. Bitfields têm `<nome>()`/`set_<nome>()` e as
  constantes `<NOME>_SHIFT`/`<NOME>_MASK`.
- **A fronteira é o único `unsafe`.** O adaptador do export converte o
  argumento uma vez (`unsafe { Irp::at(call.arg(1)) }`) e a rotina do assunto
  recebe `&Irp`, como as do NT recebem `PIRP`:

  ```rust
  fn complete_request(irp: &Irp, status: i32, information: u64) {
      irp.io_status.status.set(status);
      irp.io_status.information.set(information);
  }
  // contador compartilhado: atômico de verdade
  header.pointer_count.atomic().fetch_add(1, Ordering::SeqCst);
  ```
- **Atômicos para o que é compartilhado**: contadores de referência, locks,
  push locks, flags alteradas por outra CPU e todo `Interlocked*` usam
  `field.atomic()` (instruções `lock`). Nunca ler-modificar-escrever em duas
  chamadas.
- **Sondas só para ponteiros não confiáveis** (vindos do modo usuário):
  `Tipo::try_at(endereço)` sonda o objeto inteiro (o `ProbeForRead`) e
  `probe_get`/`probe_set` fazem cada acesso por `try_read`/`try_write` de
  `mm/guest_memory.rs`, que devolvem `STATUS_ACCESS_VIOLATION` — o equivalente
  do `__try/__except`. Memória do kernel e de drivers não é sondada.
- **Posse da memória de usuário (modo estrito)**: ligado em todo boot (a
  suíte e o boot normal) quando o anel 3 é armado
  (`ps/user/index.rs::init`). Toda sonda de uma VA de usuário
  (`try_read`/`try_write`/`*_bytes`, `read_bytes`/`write_bytes`, os atômicos,
  `probe_get`/`probe_set` e `try_at`) confere, antes do acesso, que a página
  presente é do VAD do processo corrente (`KTHREAD.ApcState.Process`, o
  anexado durante um attach) ou de uma faixa de sistema que todo processo
  vê na mesma VA: a visão de usuário da KUSER_SHARED_DATA, as regiões
  compartilhadas (NLS), as vistas de sistema e as imagens mapeadas uma vez
  (ntdll e apiset). O verificador é `ps/user/memory.rs::check_user_access`,
  instalado em `guest_memory::set_ownership_check`. Uma página do VAD de
  outro processo, ou presente e sem dono, para o sistema com `*** PANIC`
  (VA, dono, processo e thread correntes e a linha do chamador, propagada
  por `#[track_caller]` nas rotinas de sonda); uma VA sem página só dá
  ACCESS_VIOLATION, como num espaço próprio. Quem toca a memória de outro
  processo anexa ao dono antes (seção 4). Os acessos confiáveis
  (`get`/`set` e `guest::read`/`write`) não passam pela sonda e não são
  conferidos.
- **Código novo não escreve offsets à mão** (`base + 0x30`, `guest::read32(x +
  CONSTANTE)`). As constantes de `nt_abi.rs` continuam enquanto as chamadas
  antigas migram; cada uma que corresponde a um campo real é conferida em
  compilação contra `inc::types` (o bloco no fim do arquivo).

### 3.4 Mapa de memória e endereços físicos

A fonte de verdade é `ntos/mm/memory_map.rs` (o stage2 e o `xtask` incluem
o mesmo arquivo). Como no NT, tudo o que é do kernel fica na metade de
sistema (a partir de 0xFFFF8000_00000000) e a metade de usuário, PML4[0..256),
pertence só aos processos:

| VA | Índice da PML4 | Conteúdo |
| --- | --- | --- |
| 0xFFFF8000_00000000 | 256 | tabelas de páginas (mapeamento recursivo) |
| 0xFFFF8080_00000000 | 257 | banco de PFNs nativo (MmPfnDatabase): MMPFN[pfn] em base + 48 * pfn, só as páginas dos frames do bloco mapeadas |
| 0xFFFFA000_00000000 | 320 | pool executivo, PTEs de sistema dos MDLs (0xFFFFA001_40000000..0xFFFFA001_80000000), dump, memória contígua e independente, visões de sistema, VirtualAlloc de kernel, VAs globais das sessões (0xFFFFA006_80000000), pilhas de kernel das threads (0xFFFFA007_00000000..0xFFFFA008_00000000) |
| 0xFFFFB000_00000000 | 352 | **mapa direto**: a faixa física [0, topo da RAM) em `DIRECT_MAP_BASE + PA` (os 4 GB de baixo pelo stage2, o resto pelo `mm/direct_map` no boot) |
| 0xFFFFC000_C0000000 | 384 | **janela do heap**: heap do kernel (kmalloc, o alocador do Rust) sobre os frames de 32 MB a 96 MB e a arena dos convidados (IRPs, DEVICE_OBJECTs, MDLs, ExAllocatePool2...) sobre os de 256 MB a 272 MB, na VA `KERNEL_HEAP_BASE + 224 MB` |
| 0xFFFFF780_00000000 | 495 | KUSER_SHARED_DATA (visão do kernel) |
| 0xFFFFF800_00000000 | 496 | KPCR, pool de dados, a **imagem do kernel** (0xFFFFF800_40000000), a pilha de boot (topo em 0xFFFFF800_41200000) e a janela de imagens de kernel (0xFFFFF801_00000000..0xFFFFF802_00000000) |
| 0xFFFFF900_00000000 | 498 | **espaço de sessão**: tabela de topo própria de cada sessão (vazio na raiz do System e dos processos sem sessão); SessionCore, VA dinâmica (pool de sessão) e imagens de sessão |

**Memória física.** O bloco de memória física (`mm/physical_layout.rs`, o
MmPhysicalMemoryBlock) é toda a RAM do mapa E820, abaixo e acima de 4 GB
(até o slot do mapa direto, 512 GB, e a largura física da CPU), menos os
descritores reservados, ACPI e NVS e menos a página 0 (o primeiro PFN do
bloco é 1, como num 19041). Dele saem o
MmNumberOfPhysicalPages, o MmLowestPhysicalPage e o MmHighestPhysicalPage,
os únicos totais que o sistema mostra: SystemBasicInformation (classes 0,
62 e 114), as classes 182 e 184, o NumberOfPhysicalPages da
KUSER_SHARED_DATA, o total da partição, o commit inicial e o banner. O
alocador de frames (`mm/pfn.rs`, um bit por frame) recebe o bloco inteiro
menos `memory_map::PFN_EXCLUDED`, a memória que o kernel ocupa desde o boot
(as tabelas e células abaixo de 1 MB, a imagem, a pilha de boot, a tabela do
censo, o heap e os frames da arena dos convidados), como o MiInitializePfnDatabase põe na lista livre só os
descritores livres do carregador. Esses frames ficam no banco nativo como
páginas em uso. A lista livre do banco nativo é encadeada na ordem dos
frames, a partir do bitmap. Logo depois do alocador, o `mm/direct_map`
estende o mapa direto do stage2 até o topo da RAM (uma PD por GB acima de
4 GB, em frames do PFN, com as mesmas páginas de 2 MB) e só então o
`hal::physical` aceita endereços acima de 4 GB (`direct_map_limit`). O banco
de PFN nativo (`mm/native_pfn_database.rs`) é mapeado esparso, como no
MiMapPfnDatabase: só as páginas da janela que guardam descritores de frames
do bloco têm frame (não contíguos), e os descritores são lidos pela VA da
janela; um frame fora do bloco (o buraco de PCI, por exemplo) não tem
descritor.

**Imagem do kernel.** O ntoskrnl é ligado na sua VA de sistema, como no NT:
a ImageBase do PE é `KERNEL_VIRTUAL_BASE` = 0xFFFFF800_40000000 (cabeçalhos
na primeira página, `.text` em +0x1000), e é essa base que a lista de módulos
carregados, o KDDEBUGGER_DATA64 e o `RtlPcToFileHeader` veem. O stage2 lê o
arquivo do disco para os frames a partir de 1 MB (offsets do arquivo == RVAs)
por DMA de barramento: acha no barramento PCI 0 o controlador IDE com o canal
primário em 0x1F0 e bus master (classe 01.01, BAR4), liga o bus master no
comando PCI e lê até 256 setores por READ DMA, com uma tabela PRD de duas
entradas de 64 KB. Sem esse controlador, ou com erro num comando, o resto
sai por ATA PIO, um setor por comando. Cada porta de I/O é uma saída da
máquina virtual no WHPX e uma chamada ao emulador no TCG: os 16 MB do kernel
por PIO levavam 10 s no TCG e 22 s no WHPX. O stage2 então
confere o cabeçalho (ImageBase, SizeOfImage, entrada) e mapeia exatamente
SizeOfImage páginas de 4 KB de supervisor, RW e executáveis na ImageBase, com
tabelas fixas em 0x83000-0x92FFF (PDPT, PD e catorze PTs). A pilha de boot é
outra VA de sistema na mesma PD: 383 páginas RW e NX terminando em
`BOOT_STACK_TOP`, sobre os frames logo abaixo de 30 MB (a imagem pode ir até
27,5 MB, nos frames de 1 MB a 28,5 MB; a tabela do censo do heap ocupa os
2 MB entre a pilha e o heap), com uma página de
guarda sem mapeamento embaixo (PT em 0x93000). As tabelas ficam abaixo da
EBDA (0x9F000), e o campo de 16 bits com os setores do kernel no stage2
limita o arquivo a 32 MB. O stage2 carrega o GDTR pela VA
do mapa direto e entra no kernel com RSP = BOOT_STACK_TOP - 8 e RBP zero (o
fim da cadeia de quadros).

*Seções de código.* A imagem tem duas: `.text` e, logo depois, `PAGE`, como
no ntoskrnl. As duas levam CNT_CODE, MEM_EXECUTE, MEM_READ e MEM_NOT_PAGED
(0x68000020); o OpenNT não pagina o kernel, então a PAGE fica residente. A
PAGE recebe as seções de entrada `.text.page` (`kernel/link.ld`; o padrão da
`.text` aceita todo `.text.*` menos esse nome) e guarda os corpos que drivers
acham pelos bytes. Alguns drivers chegam a rotinas que o ntoskrnl não exporta
seguindo um CALL conhecido: o MmAllocateIndependentPages pelo CALL de
KeAllocateProcessorProfileStructures+0xc6 (`33 D2 48 8B CE E8`, depois de
`add rsi,0FFFh; and rsi,-1000h`), o MmFreeIndependentPages pelo
MmFreeIsrStack (`40 53 48 83 EC 20 48 8D 99 00 A0 FF FF BA 00 60 00 00 48 8B
CB E8`) e o PsEnumProcessThreads pelo PopUpdateSingleProcessHeteroPolicies
(`48 83 EC 28 45 33 C0 48 8D 15 22 00 00 00 E8`) e pelo
EtwpProcessEnumCallback (`4C 8B C6 48 8D 15 rel32 48 8B CB E8`). Em
`hal/amd64/private_entries.rs`, cada um desses corpos repete a sequência do
ntoskrnl 19041 até o CALL (no EtwpProcessEnumCallback, a da chamada), byte a
byte menos os deslocamentos relativos, e segue com o código do OpenNT. As três rotinas privadas ficam na PAGE (um stub
que marca o id e cai no trampolim comum), assim como o MmFreeIsrStack
(a pilha de ISR de `mm/independent_pages.rs`: guarda embaixo e 0x6000 bytes
de pilha), o PopUpdateSingleProcessHeteroPolicies (com o callback de
`ke/hetero_policy.rs`) e o EtwpProcessEnumCallback (com o callback de
`etw/rundown.rs`); o KeAllocateProcessorProfileStructures é um export com
corpo nativo na `.text` (`ke/processor_profile.rs`). O logger do OpenNT ainda
não grava o rundown clássico do NT Kernel Logger: o EtwpThreadEnumCallback só
marca no contexto o tipo do evento (DCStart de thread).

*Modelo de código.* O alvo `x86_64-unknown-none` usa o code model `kernel`,
cujos endereços absolutos de 32 bits só alcançam os 2 GB do topo; ligar em
0xFFFFF80x exige outro arranjo. O escolhido é gerar o código independente de
posição (`-C relocation-model=pic` em `.cargo/config.toml`, o mesmo modelo em
que a `core` e a `alloc` pré-compiladas do alvo já vêm) e ligar um executável
estático (`--no-pie` nos `build.rs`): toda referência do código é relativa a
RIP, os ponteiros absolutos dos dados (vtables, tabelas de despacho, `.quad`
dos stubs) são resolvidos pelo linker na VA final, e não há relocação para o
stage2 processar. `.data.rel.ro` vai para `.rodata` no `link.ld`. Medido no
build de testes, com o mesmo código-fonte: `.text` tem 8.137.799 bytes, 0,22%
a mais que o código de relocação estática ligado em 1 MB (8.119.815), e
`.rodata` + `.data` ficam iguais. As alternativas ficaram de fora: o code
model `large` (relocação estática em 0xFFFFF80x) leva `.text` a 8.954.361
bytes (+10,3%), porque toda chamada direta vira `movabs` + chamada indireta e
todo acesso a global carrega o endereço de 64 bits antes; processar
relocações no stage2 exigiria um carregador de PE em modo real/protegido para
um resultado que o linker já entrega; e ligar nos 2 GB do topo
(0xFFFFFFFF_80000000) poria o ntoskrnl fora da faixa em que o NT o carrega e
que drivers e depuradores esperam.

**Metade de usuário.** O stage2 só mapeia na metade baixa a página de 2 MB
em que ele mesmo liga a paginação (PML4[0], tabelas em 0x71000-0x72000), e
o kernel a desfaz na primeira instrução depois de zerar o BSS
(`paging::remove_boot_identity`). Os APs ganham o mesmo tratamento do stub
baixo do NT: a página do trampolim (0x9000) é mapeada em identidade
(supervisor, executável) só enquanto eles partem; o trecho de 64 bits do
trampolim salta para `ap_kernel_entry`, na imagem do kernel, onde o AP troca
para a GDT e a IDT da imagem e roda o laço de jobs e o handler de NMI; com
todos online, o BSP desmapeia a página, invalida as traduções em todas as
CPUs e devolve as tabelas ao PFN. No fim da fase 0,
`mm/user_half.rs::assert_user_only` percorre PML4[0..256) e para o sistema se
achar qualquer folha presente de supervisor; o autoteste
`ntos/test/user_half.rs` repete a varredura no fim das fases 6 e 7, depois
dos drivers reais e dos programas de usuário, e confere que nenhuma
estrutura do kernel tem identidade baixa. Na metade de usuário só ficam
páginas de usuário: imagens, pilhas, TEB/PEB, seções e a visão somente
leitura da KUSER_SHARED_DATA em 0x7FFE0000 (a do kernel fica em
0xFFFFF780_00000000).

**Bloco por CPU.** Cada processador tem a sua KPCR (`ke/pcr.rs`), uma
reserva de 0xC000 bytes em `PCR_VIRTUAL_BASE + número * 0xC000`, publicada no
IA32_GS_BASE da própria CPU: o BSP a carrega em `pcr::init`, e cada AP na
entrada (`ap_kernel_entry`), com a KPCR que o BSP montou antes do SIPI (o
número é 1 + a posição do AP entre os online, o mesmo bit de
`active_mask`). No anel 0 o GS é sempre a KPCR; o GS do usuário (a TEB) fica
no KernelGSbase, e o SWAPGS troca os dois logo depois da entrada (syscall ou
interrupção vinda do anel 3) e logo antes do IRETQ. A entrada de syscall é a
do KiSystemCall64: `swapgs; mov gs:[10h], rsp; mov rsp, gs:[1A8h]`, a pilha
do usuário na KPCR.UserRsp e a de kernel da KPRCB.RspBase (o mesmo valor da
TSS.RSP0), e a KTHREAD corrente em gs:[188h]. O resto do estado de uma
execução no anel 3 (RSP do despachante, CONTEXT do intervalo, tipo e código
da saída, NtContinue, falta, captura de chamada, os bancos de depuração e o
callback de instrumentação) é o `UserExecutionBlock` da CPU
(`hal/amd64/usermode.rs`, campos `Field<T>`), na cauda da reserva, depois da
KPCR de 0xB080 bytes: os stubs o endereçam por `gs:` e o Rust por
`usermode::block()` e `pcr::current()`. O IRQL também é da CPU, e é o CR8
dela, como no x64 do NT 19041 (`ke/irql.rs`): o KeGetCurrentIrql é um
`mov rax, cr8` e o KfRaiseIrql, o KeRaiseIrqlToDpcLevel e o KeLowerIrql
gravam o CR8 (o ntoskrnl não usa a KPCR.Irql), o mesmo registrador que os
drivers leem e gravam inline (o KeGetCurrentIrql do wdm.h, como os 156
`mov rax, cr8` do tcpip.sys): subir pelo export e descer inline, ou ler
inline depois de subir pelo export, vê o nível verdadeiro. O CR8 é a classe
de prioridade do TPR do LAPIC: um IRQL `n` retém no LAPIC os vetores de
classe até `n` (o timer do LAPIC, vetor 0x40, a partir de 4), como no NT; o
ExtINT do PIC e as NMIs não passam pelo TPR, e a partida do LAPIC regrava o
TPR com o próprio IRQL. As ISRs nativas rodam no IRQL do objeto (o
SynchronizeIrql, quando maior) com o ActualLock retido, como o despacho
encadeado do ntoskrnl (`interrupt_object::dispatch_chain`). O stub de IRQ
do PIC só conta e dá o EOI, e a ISR roda depois; uma linha sensível a
nível (um objeto LevelSensitive conectado nela, a INTx do PCI) fica
mascarada no PIC desde o stub até a cadeia dela rodar (`LEVEL_LINES`), senão
o dispositivo que ainda segura a linha reentraria sem fim. O
KeStallExecutionProcessor de um driver atende, durante a espera, as
interrupções de dispositivo e as DPCs pendentes, como a preempção do NT faz
com a CPU que gira (o stornvme.sys espera assim pela conclusão das filas). Uma thread que
deixa a CPU leva o CR8 em KTHREAD.WaitIrql e o recoloca ao voltar
(`context_switch`); cada CPU parte com o seu em 0 (o INIT o zera), e o
depurador do kernel lê o de cada processador parado. A execução em curso do `ke/thread_dispatch` (o contexto ativo, a
pilha de execuções aninhadas e o início da contagem de ciclos) é de cada CPU;
as filas prontas e o lock delas são uma fila só, a da KPRCB do BSP, para
toda CPU que despacha (como a KSHARED_READY_QUEUE que o 19041 divide entre
até quatro processadores), e cada CPU reserva a escolhida na NextThread da
própria KPRCB (veja **Threads de usuário em várias CPUs**, abaixo). O anel 3
só entra numa CPU armada (assert em
`exec_user_mode`/`exec_user_context`): como o KiInitializeProcessor do 19041
dá a cada processador a GDT, a TSS, a IDT, as pilhas e os MSRs de syscall,
`usermode::processor_user_mode_init` monta a GDT da CPU (a de boot com os
dados e o código de usuário em 0x28/0x30 e a TSS de 16 bytes em 0x38) e a
TSS (RSP0 = a pilha reserva da CPU, IST1 = a da falta dupla) na reserva da
KPCR dela (`pcr::layout::PROCESSOR_GDT`/`PROCESSOR_TSS`), publicadas em
KPCR.GdtBase/TssBase, e grava o EFER.SCE, o STAR, o LSTAR, o SFMASK e a
KPRCB.RspBase. O estado de execução de usuário (em curso, o CONTEXT da
syscall, o quadro do serviço, a pilha reserva) e as faixas preservadas do
CONTEXT são de cada CPU, pelo número do processador; uma syscall que
bloqueia leva os dela e os recoloca na CPU que a retoma. O stub de syscall
relê o RBX (a KPCR) depois do serviço: um serviço que bloqueou numa CPU e
foi retomado em outra volta pela KPCR da CPU que o retomou (a pilha do
usuário, o NtContinue e o callback de instrumentação dela). O BSP se arma no
`user_mode_init`; um AP, pelo `smp::start_scheduling` (no boot com a opção
`--user-smp`, USERSMP, ou pelo autoteste): o trabalho dele recebe a cópia
da IDT do BSP (com o vetor 8 na IST1 e o vetor 2 na NMI dos APs, que acha o
slot pelo LAPIC, sem GS), se arma, liga o timer local no vetor 0x41 (o
0x40 continua sendo o relógio global do BSP; o stub conta os tiques do AP
na KPCR dele e trata o 0x41 como o 0x40 no fim de um intervalo de usuário)
e fica no laço ocioso (`smp::processor_loop`, o KiIdleLoop do 19041): atende
os trabalhos da mailbox, dá intervalos às threads de usuário prontas (com o
despacho de usuário ligado, `smp::enable_user_dispatch`) e, sem trabalho nem
thread pronta, dorme no `sti; hlt`; o `start_job` manda, depois da NMI, o
IPI de reescalonamento (vetor 0xE1, o do HalpInterruptSendIpi), que fica
pendente no IRR até o HLT. As linhas da serial têm uma trava
própria com espera limitada (`rtl::print`), para duas CPUs não misturarem
linhas. O autoteste `ntos/test/multiprocess/per_cpu.rs` confere os blocos
distintos de cada CPU e uma syscall de teste que devolve gs:[10h] igual ao
RSP do usuário; o `ntos/test/multiprocess/processor_ring3.rs` arma os APs e
confere as tabelas de cada um (a GDT e a TSS na reserva da KPCR, distintas
entre as CPUs, com as pilhas que o AP recebeu, a IDT própria com o vetor 8
na IST1, o LSTAR, o STAR, o SFMASK e o CR4 do BSP), o timer local, o anel 3
cru no CPU 1 (a syscall atendida nele) e uma syscall que bloqueia no BSP e
é retomada no CPU 1 com a KPCR.UserRsp do BSP envenenada: a volta ao anel 3
sai pela KPCR do CPU 1.

**Thread corrente por CPU.** Como no NT, a thread corrente é a
KPRCB.CurrentThread da KPCR de cada processador: `ps::process::
get_current_thread` (o KeGetCurrentThread, e por ele PsGetCurrentThread,
PsGetCurrentProcess e os demais que partem da thread corrente) lê gs:[188h]
da CPU que executa, e `set_current_thread`, o ponto único de troca de
thread, grava só a célula da própria CPU (`pcr::set_current_thread`, pelo
GS) antes de carregar a raiz do processo dela. Não há célula global: uma
troca num AP não muda o que o BSP vê, e um AP que nunca trocou de thread
tem 0 (o contexto do System, como o BSP antes do escalonador). A troca
para uma thread que não é de sistema também grava em KPCR.Used_Self
(gs:[30h]) a KTHREAD.Teb dela, como o SwapContext do 19041, que pula esse
estado de usuário numa thread de sistema (o Used_Self fica o da última
thread de usuário): é o NtCurrentTeb do anel 0, e o win32kbase aponta por
ele o pClientInfo de cada THREADINFO para TEB.Win32ClientInfo (gs:[30h] +
0x800), onde grava o CallbackWnd que a user32 lê nos callbacks de janela
(o WM_NCCREATE de toda janela de cliente). O autoteste
`ntos/test/multiprocess/current_thread.rs` põe cada CPU online, ao mesmo
tempo, numa thread de um processo de kernel só dela (os APs por um job,
entre duas barreiras), cada uma como thread que não é de sistema com uma
Teb sintética própria: cada uma vê em gs:[188h] a própria thread, dela o
próprio processo e TID, e em gs:[30h] a Teb dela, e o PsGetCurrentThread
do BSP no meio da janela devolve a dele; a volta a nenhuma thread ou a uma
de sistema deixa a Teb em gs:[30h].

**Threads de usuário em várias CPUs.** Com a opção de boot `--user-smp`
(USERSMP), cada AP armado também despacha threads de usuário: o laço ocioso
dele escolhe a pronta de usuário mais prioritária que pode rodar
(`thread_dispatch::peek_for`, o KiSelectNextThread; as threads de sistema,
KTHREAD.MiscFlags.SystemThread, ficam no BSP) e lhe dá um intervalo
(`threads::dispatch_on_processor`). Os pumps, as sondagens das esperas, as
DPCs, as IRQs, os timers, as threads de kernel, os fins de processo e o
recolhimento das threads continuam no BSP; o fim de processo que um
intervalo de AP pede e as threads mortas vão a ele por uma fila
(`EXIT_REQUESTS`), e o BSP ocioso é acordado. A posse de uma thread segue
19041: ela é de no máximo uma CPU, que a executa (Running) ou a reservou
(Standby), pelo KTHREAD.NextProcessor, e só essa CPU mexe no estado de
execução dela (o CONTEXT, a pilha de kernel, a espera instalada, as APCs
de kernel). Quem trata uma thread fora da CPU no lugar dela (a sondagem da
espera, as APCs de kernel drenadas no contexto dela, o término direto) a
toma emprestada (`thread_dispatch::try_borrow`): emprestada, nenhuma outra
CPU a escolhe, e a prontidão que chega a deixa DeferredReady (o
KiEnterDeferredReadyState) até a devolução. A thread deixa de ser Running só
no fim do intervalo, com o estado novo decidido sob o PrcbLock
(`end_execution_with`, a ideia do KiCommitThreadWait): uma retomada, uma
conclusão ou um término de outra CPU antes da decisão é visto nela, e um
depois encontra a thread fora da CPU (a suspensão e a retomada também
decidem sob o PrcbLock). O término, a suspensão e o fim do processo
pedidos para uma thread que outra CPU executa valem no fim do intervalo
dela: a espera instalada conclui pela dona (`deferred_termination`), a
thread sem estado do win32k termina no próprio contexto (o
KeRequestTerminationThread), e o IPI de reescalonamento à dona encerra o
intervalo no anel 3 (o stub trata o 0xE1 como o timer) ou a saída do
serviço vê o pedido. A prontidão acorda uma CPU que pode rodar a thread (o
KiDeferredReadySingleThread com o KiChooseTargetProcessor): uma ociosa (o
bit dela entra nas ociosas antes da última conferência com as
interrupções desligadas, o KiSetProcessorIdle), senão o AP que roda a
thread de usuário de menor prioridade abaixo dela; a APC enfileirada para
uma thread em outra CPU manda o IPI à dona (o KiSignalThreadForApc), que
entrega as APCs de kernel antes do intervalo seguinte. Uma PTE presente que
muda numa VA de usuário invalida as outras CPUs com a raiz carregada
(`smp::flush_root`, o KeFlushTb do espaço de endereçamento: o registro da
raiz de cada CPU é publicado antes da carga do CR3), e uma da metade de
sistema invalida todas menos as ociosas no HLT, que descartam a TLB ao
acordar, como o KiFlushTb do 19041 (`smp::flush_kernel_page`; as
desmontagens de várias páginas invalidam uma vez no fim do lote,
`MapOptions::batch_remote`); o BSP atende a NMI de shootdown pela
confirmação dele na mailbox, dois shootdowns ao mesmo tempo esperam a vez,
e a espera manda de novo, a cada 20 ms, a NMI a quem não confirmou (sob o
WHPX, o QEMU injeta a NMI com a CPU ainda dentro do tratador da anterior e
ela se perde; o BSP conta as repetidas e as descarta). A exceção, a falta
de página e a captura de chamada de um intervalo são tratadas com a thread
ainda Running na CPU dela, antes do fim da execução (o KiDispatchException
roda no contexto da thread). A escolha de uma faixa livre de VA
de usuário e o registro dela no VAD são um passo só, sob a
AddressCreationLock do processo (`memory::address_creation`); os frames
do commit e da control area vêm fora dela (com um SharedLock retido o PFN
não roda o modified page writer na hora). A thread
criada suspensa vai direto à espera, com a decisão tomada sob o PrcbLock
pela contagem de suspensão (`attach_scheduling`), sem passar pela fila. A
posse de uma thread consultada fora da CPU dela lê o ponteiro da KTHREAD
sob a trava da thread (a liberação da morta o zera sob a mesma trava). Nas
seções, a busca da control area de um arquivo e a referência nova
(`sections::create`) e a última referência (`destroy_section`) são
decididas sob a trava de FILE_AREAS, e as páginas novas de uma seção de
imagem ou de arquivo são preenchidas em frames ainda fora da control area e
só então publicadas (a falta de outra CPU na mesma página nunca mapeia um
frame ainda por ler; a que outra CPU publicou no meio fica). Um pulso (ou
o sinal seguido do reset) que outra CPU dá entre a instalação de uma espera
adiada e a ligação dos blocos dela a satisfaz na ligação, como satisfaria a
do 19041, ligada dentro do serviço. Uma espera que gira num AP (o
`wait_until` de quem retém uma trava) entrega as conclusões e as APCs de
kernel da própria thread; o BSP que disputa um SharedLock atende as IRQs e
as DPCs e roda as threads de kernel quando não pode dar intervalo de
usuário. A linha `[perf] t=N ms aps:` soma os intervalos e o HLT dos APs, os
empréstimos recusados, os IPIs de reescalonamento e os shootdowns; com o
sistema parado por 15 s (o BSP ocioso e nenhum intervalo de usuário), sai
uma vez uma linha `[parada]` por thread de usuário, com o estado de
despacho, a CPU dona, a presença na fila, a suspensão, o serviço e a espera,
e uma por porta ALPC ou servidor com pedidos pendentes
(`threads::report_stalled_threads`). Com `--user-smp` o boot até a área
de trabalho ainda tem paradas longas (um pedido ALPC síncrono recebido pelo
servidor, o LSM ou o csrss, fica sem resposta até um prazo vencer), e os
testes da cadeia continuam com `--smp=1`. O
autoteste `ntos/test/multiprocess/user_smp.rs` (com dois processadores ou
mais) liga o despacho de usuário nos APs e, com o BSP só girando, confere
que o serviço é atendido num AP, que cada sinal do BSP conclui exatamente
uma espera adiada de uma thread num AP sem o anel 3 ver STATUS_PENDING,
que a thread que se suspende a cada serviço é retomada pelo BSP 500 vezes
sem perder nenhuma, que o fim do processo pedido pelo BSP encerra as
threads que giram no anel 3 dos APs e que a página liberada pelo BSP falta
na leitura seguinte da thread do AP.

**Identidade de cada CPU.** Cada processador monta a própria KPRCB com o
próprio CPUID, como o ntoskrnl 19041 no boot de cada CPU
(`ke/processor_identity.rs`): o BSP logo depois de `pcr::init`, cada AP por
um job depois de `smp::init`. São o KiGetCpuVendor (VendorString e
CpuVendor: 1 AMD/Hygon, 2 Intel, 3 Centaur), o KiGetProcessorSignature
(CpuType, CpuStep, CpuID), o KiSetProcessorSignature (o FeatureBits de 64
bits pela KiCpuFeatureTable — 47 testes de bit do CPUID com filtro de
fabricante, iguais aos do ntoskrnl 19041 — e pelas tabelas de MSR do
IA32_ARCH_CAPABILITIES; os bits do segundo conjunto em KeFeatureBits2;
ProcessorFlags e ProcessorSignature), o KiSetFeatureBits (os recursos
exigidos, o bit do fabricante, SLAT e firmware de virtualização,
InitialApicId, CFlushSize, lógicos por núcleo e núcleos por pacote pelas
folhas 0x1F/0xB/4/1 ou 0x80000008/0x8000001E, ApicMask, UpdateSignature e o
IA32_TSC_AUX), o KiSetCacheInformation (Cache[], CacheCount, o L2 da KPCR,
KeLargestCacheLine e KiLargestCacheSize) e a frequência (MHz e
StallScaleFactor). Com todos online, os conjuntos do KiInitializeKernel:
PackageProcessorSet, PackageId, CoreProcessorSet e CacheProcessorMask. O
KeFeatureBits é o FeatureBits do BSP com o NX (EFER.NXE) e os bits do XSAVE
(KF_XSTATE, KF_XSAVEOPT e KF_XSAVES, de `ke/xsave.rs`, abaixo); dele saem os
PF_* da KUSER_SHARED_DATA pela
lista do KiInitializeKernel e do KiPublishProcessorFeatures, o
SystemProcessorInformation e o SystemProcessorFeaturesInformation. O
KeQueryLogicalProcessorRelationship, o SystemLogicalProcessorInformation
(o KeBuildLogicalProcessorSystemInformation) e o
NtQuerySystemInformationEx(107) de modo usuário leem essas KPRCBs, e o
KeQueryPrcbAddress devolve a de cada processador. O que o binário muda na
CPU nessa passagem e o OpenNT não repete — CR4 (SMEP, FSGSBASE, SMAP, UMIP,
PCIDE), EFER.FFXSR, MSRs de SYSENTER, MISC_ENABLE e DE_CFG — fica de fora, e
SMEP e FSGSBASE só entram no FeatureBits com o bit do CR4 ligado, como no
NT, que os liga juntos. Os conjuntos KAFFINITY_EX (Initialize, Add/Remove/
CheckProcessor, IsEmpty, IsEqual, Copy, Or, And, AddGroup, CountSetBits), o
KeFindFirstSetLeftGroupAffinity, o KeQueryActiveProcessorAffinity e o
KeEnumerateNextProcessor, que os drivers de energia do processador
(processr.sys, amdppm.sys, intelppm.sys) importam, seguem as rotinas do
binário em `ke/affinity_set.rs`. O autoteste
`ntos/test/multiprocess/processor_identity.rs` confere cada KPRCB com o
CPUID do próprio processador, os PF_* com o CPUID (e a visão de usuário que
o IsProcessorFeaturePresent lê) e as consultas pela chamada de sistema.

O estado estendido do processador (XSAVE) segue o ntoskrnl 19041 em três
arquivos. `ke/xsave.rs` faz o KiInitializeXSave de cada CPU antes do
KiSetFeatureBits: no BSP, os recursos do CPUID 0xD (KiGetXSaveSupportedFeatures:
o x87 e o SSE obrigatórios, OptimizedSave pelo XSAVEOPT, compactação com o
XSAVEC e o XSAVES, os recursos de supervisor do IA32_XSS só com a
compactação, AllFeatures e AlignedFeatures), a XsaveAllowedFeatures e os
XsaveFlags de um carregador sem opções de BCD (todos os recursos, mantendo
OptimizedSave e compactação), a política do hwpolicy.sys
(KiIntersectFeaturesWithPolicy: o recurso 0x65, nome 1, do driver de política,
que entra no bundle do kernel como os drivers de boot do carregador; um
recurso fica só se a política o lista e a entrada do fabricante aceita a
assinatura e o microcódigo; sem o driver, nenhum recurso), Size,
AllFeatureSize e os deslocamentos no formato compactado
(KiUpdateXSaveSizeAndVolatileFeatures), os voláteis e o supervisor visível;
KeXStateLength = KiXSaveAreaLength = AllFeatureSize. Num AP, o CPUID dele
precisa cobrir a configuração do BSP (aviso no lugar do bugcheck). O
KiInitializeKernel acrescenta KF_XSTATE, KF_XSAVEOPT e KF_XSAVES
(KeGetXSaveFeatureFlags), e o KiEnableXSave de cada CPU liga o CR4.OSXSAVE,
grava o XCR0 = EnabledFeatures e o IA32_XSS. A configuração é publicada em
KUSER_SHARED_DATA.XState antes dos PF_* (PF_XSAVE_ENABLED, PF_AVX, PF_AVX2,
PF_AVX512F dependem dela). O RtlGetEnabledExtendedFeatures e o
RtlGetEnabledExtendedAndSupervisorFeatures (`rtl/version.rs`) leem dela.

`ke/xstate.rs` é o estado de cada thread e o dos drivers. A KTHREAD tem a
área de XSAVE em StateSaveArea, no topo da pilha de kernel (StackBase -
KiXSaveAreaLength, alinhada a 64, com o KERNEL_STACK_CONTROL e o
InitialStack logo abaixo, como no KiInitializeContextThread); as threads da
pilha de boot usam a área do despachante da CPU 0, e cada despachante tem a
sua. A área nova é zerada; numa thread de usuário (`UserThread::new`) leva a
palavra de controle x87 0x27F e o x87 no XSTATE_BV; com a compactação,
XCOMP_BV = bit 63 | x87 | SSE. NpxState é o do KiSetSwitchingNpxState. O
salvamento é ansioso, como no SwapContext, com as primitivas de
`hal/amd64/extended_state.rs`: XSAVES com KF_XSAVES, senão XSAVEOPT com
KF_XSAVEOPT, senão XSAVE; XRSTORS ou XRSTOR na volta; a máscara é a dos
recursos habilitados sem x87 e SSE (os dois seguem no CONTEXT do intervalo e
nos quadros de troca); o MXCSR vivo volta intacto. Os pontos de troca: o fim
de todo intervalo de usuário (`user_terminate_current`: syscall, relógio,
exceção, bloqueio no kernel, término) salva na área da thread; a entrada
(`user_exec_context`, antes do FXRSTOR do CONTEXT) e a retomada de uma
thread bloqueada (`opennt_resume_thread`) recarregam dela; um callback de
modo usuário parte do estado vivo do serviço de fora; as trocas entre o
despachante e as threads de kernel salvam e recarregam a área do lado que sai
(`ke/context_switch.rs`, o `CarriedState`), e a primeira entrada de uma
thread de kernel carrega a área inicial. O UserExecutionBlock da CPU guarda
a área da thread do intervalo (`xstate_area`, zero no anel 3 cru).
KeSaveExtendedProcessorState e KeRestoreExtendedProcessorState seguem o
KeSaveExtendedAndSupervisorState e o KeRestoreExtendedAndSupervisorState: a
máscara conferida contra os recursos habilitados
(INVALID_EXTENDED_PROCESSOR_STATE), todos os recursos habilitados sem x87 e
SSE salvos, o nível (0 em PASSIVE fora de APC de kernel, senão IRQL + 1), a
lista KTHREAD.XStateSave, a área do pool (KeAllocateXStateContext, max(0x240,
Size) + 63) ou, em DISPATCH_LEVEL, a KPRCB.ExtendedState, e o RtlXSave e o
RtlXRestore (XSAVEC/XSAVES com a compactação; sem ela, o cuidado do MXCSR
com o AVX sem o SSE). KeSaveFloatingPointState e KeRestoreFloatingPointState
só devolvem STATUS_SUCCESS, como no x64. Enquanto a lista não está vazia, o
estado de usuário da thread é o da área mais antiga dela (o que o
KeContextFromKframes e o KxContextToKframes consultam).

`rtl/extended_context.rs` tem as rotinas internas do CONTEXT estendido
(RtlpValidateContextFlags, RtlGetExtendedContextLength2,
RtlInitializeExtendedContext2, RtlpGetEntireXStateAreaLength,
RtlpGetNonLegacyXStateAreaLength, RtlpCopyXStateChunk; o ntoskrnl 19041 não
as exporta, as da ntdll são as que o modo usuário usa), e
`ps/context/xstate.rs` move o pedaço XSTATE entre a
thread e o CONTEXT de usuário: o KiCopyXStateArea da área para o CONTEXT
estendido do kernel (KeContextFromKframes), a cópia sondada para o pedaço do
usuário e, na volta, a área mais antiga da lista ou a da thread, recarregada
na CPU quando a thread é a do serviço em curso (o RtlXRestoreS do
KxContextToKframes). Usam isso: o despacho de exceções
(`ps/user/exceptions.rs`, o frame do KiDispatchException: ContextFlags
0x10005F com KF_XSTATE, o pedaço XSTATE alinhado a 64 logo abaixo do RSP
interrompido, o machine frame alinhado a 16 abaixo dele, o CONTEXT a 0x590
do machine frame; All cobre do CONTEXT ao RSP, XState.Length vai até o RSP),
o NtContinue e o NtRaiseException com CONTEXT_XSTATE e o NtGetContextThread
e o NtSetContextThread de modo usuário (sem recursos habilitados,
STATUS_NOT_SUPPORTED). Um chamador de KernelMode do
PspSetContextThreadInternal (e do PsSetContextThread) passa o próprio
CONTEXT: o CONTEXT_XSTATE é aceito como no RtlpSanitizeContextFlags e, como
no PspSetContext, o pedaço que o XState do CONTEXT_EX dele aponta só vai à
thread quando o contexto de destino é o de UserMode (`ps/context/set.rs`);
num contexto de KernelMode ele é ignorado.

O frame das APCs de usuário (`ps/user/user_apc.rs`) segue o
KiInitializeUserApc do 19041: o 7º argumento dele tem o bit 1 numa APC
especial (a KernelRoutine é a KeSpecialUserApcKernelRoutine), e só então,
com KF_XSTATE, o CONTEXT leva CONTEXT_XSTATE (0x10005B) e o pedaço XSTATE
fica logo abaixo do RSP interrompido, alinhado a 64, com
RtlpGetNonLegacyXStateAreaLength da máscara (EnabledFeatures | supervisor
visível, sem x87 e SSE e, sem pilha de sombra de usuário, sem o CET_U)
bytes; o MACHINE_FRAME fica alinhado a 16 abaixo dele e o CONTEXT 0x530
bytes antes; no CONTEXT_EX, All vai do CONTEXT ao RSP, Legacy é o CONTEXT e
XState vai do pedaço ao RSP; o pedaço zerado recebe, com a compactação,
XCOMP_BV = máscara | bit 63 e o estado de usuário da thread
(KeContextFromKframes). O NtContinueEx do KiUserApcDispatcher devolve dele
a metade alta dos YMM. A APC especial interrompe o código em qualquer
instrução (no OpenNT, no começo do intervalo seguinte da thread); a APC
normal sai só no retorno de uma chamada de sistema (a espera alertável, o
NtTestAlert, o NtContinue com TestAlert), onde a ABI x64 já trata a metade
alta dos YMM como volátil, e o frame dela não tem o pedaço. A sonda da
pilha vem antes da retirada da APC, com o tamanho do frame da especial
quando SpecialUserApcPending está publicado.

Os autotestes são `ntos/test/extended_state.rs` (fase 6,
`XSTATE_KERNEL_OK`: a configuração contra o CPUID de cada CPU, os exports,
os salvamentos dos drivers e duas threads de sistema com YMM diferentes) e
`ntos/test/multiprocess/extended_state.rs` (fase 7, `XSTATE_USER_OK`: duas
threads de usuário com AVX e a ntdll real, o NtGetContextThread com
CONTEXT_XSTATE, a volta de uma exceção pelo NtContinue, um CONTEXT de
KernelMode com CONTEXT_XSTATE pelo PspSetContextThreadInternal e uma APC
especial cuja rotina sobrescreve os 16 YMM, que voltam inteiros pelo
NtContinueEx do frame).

**Laço ocioso.** Como o KiIdleLoop do 19041 chama o HalProcessorIdle, o
processador que não tem o que rodar dorme no HLT com as interrupções
ligadas (`hal::cpu::processor_idle`, `sti; hlt`: a sombra do STI cobre o
HLT, então uma interrupção que chega depois da conferência acorda o
processador na hora). No BSP, o `scheduler::idle` do laço do kmain confere
as esperas sondadas (se o tique daquela volta não acabou de conferir) e,
com as interrupções desligadas, que não há thread pronta, IRQ por
despachar nem DPC na fila e que a IRQL é PASSIVE_LEVEL; o tique do LAPIC a
100 Hz, as IRQs de dispositivo e a NMI o acordam. Um KTIMER que vence antes
do próximo tique faz o laço girar até ele, para vencer na hora. Os APs
dormem no HLT do laço de trabalhos do trampolim com o IF desligado: o
`smp::start_job` publica a rotina e manda a NMI, e a NMI que chega entre o
teste do trabalho e o HLT volta ao teste (`ap_nmi_done`), sem perder o
trabalho; os shootdowns e o congelamento do depurador já vinham pela NMI.
Antes, cada CPU virtual girava sem parar: um QEMU de 4 CPUs ainda no boot
gastava 4,3 núcleos do hospedeiro e agora gasta 1,5; o de 1 CPU parado na
tela de logon, 1,4 e agora 0,05 (o resto era a thread de entrada do QEMU,
que o test-boot agora fecha com um pipe em vez do NUL). O autoteste
`ntos/test/kernel_waits.rs` confere que o `idle` dorme e que o tique o
acorda, com as interrupções ligadas, e que um DPC na fila não o deixa
dormir.

**IPIs medidos em tempo.** As esperas de resposta a um IPI (`ke/smp.rs`)
leem o contador de desempenho (o KeQueryPerformanceCounter, 10 MHz, o mesmo
que o KiIpiGenericCallTarget do 19041 lê) em vez de contar voltas: o tempo
é o mesmo em qualquer CPU, hipervisor ou emulador. Como no 19041, as
confirmações de um shootdown de TLB e do KeFlushProcessWriteBuffers não têm
prazo (`smp::wait_on_targets`): o KeFlushMultipleRangeTb e o
KeFlushProcessWriteBuffers giram no PacketBarrier da KPRCB sem limite
(0x2bbdce..0x2bbdf8, 0x343dbd..0x343dc9), e o ICR do sistema em
funcionamento também é esperado sem prazo (o HalpApic1WriteIcr). O único
IPI_WATCHDOG_TIMEOUT (0x1DB) do 19041 é a barreira do KeIpiGenericCall
(KiIpiGenericCallTarget 0x3a49c2..0x3a4a07: 300 s a partir do
BaselineInterruptTimeQpc, e nenhum com o tempo relaxado que o hipervisor
recomenda, o bit 5 do CPUID 0x40000004), que o OpenNT não tem (o
KeIpiGenericCall roda só no processador corrente). Um alvo que demora mais
de 5 s vai à serial com os pendentes e a espera segue; a resposta tardia
também vai, com o tempo total. Antes, o shootdown parava o sistema com o
IPI_WATCHDOG_TIMEOUT depois de 5 s: sob WHPX com o hospedeiro carregado, a
CPU virtual de um AP fica segundos sem rodar (o agendador do Windows só
promove uma thread faminta depois de uns 4 s), e a suíte com 4 CPUs parava
assim no meio de um teste de registro. Só a partida dos APs (INIT/SIPI)
tem prazo, 100 ms para o ICR voltar a ocioso, por `smp::stall_on_targets`,
e devolve erro ao boot. A
comparação (`smp::deadline_passed`) é a estrita do 19041 (`ja`) e exata, em
128 bits: um prazo que não cai numa unidade inteira do contador não vence
na unidade de baixo, uma fração de unidade antes da hora. Com o TSC e o
prazo pela unidade de baixo, uma leitura que caía exatamente nela (cerca de
1 espera em 100 no QEMU sob WHPX) era detectada com 29 ms num prazo de 30.
O autoteste
`ntos/test/multiprocess/ipi_stall.rs` confere a fronteira exata do prazo,
que uma resposta que chega em 50 ms num prazo de 200 ms é aceita, que um
alvo mudo é detectado depois dos 30 ms do prazo, não antes, com contadores
coerentes, que a espera sem prazo de um alvo que responde depois do
diagnóstico conclui com ele dado como lento, e o shootdown real.
A confirmação do shootdown vem pela NMI, que nem o IF nem o IRQL (o CR8) do
alvo retêm: o mesmo autoteste faz um AP girar com as interrupções
desligadas em HIGH_LEVEL e confirma 64 shootdowns seguidos (na casa das
dezenas de microssegundos no TCG). Os 100 ms e 5 s valem em hardware e sob
hipervisor; num emulador (o TCG do QEMU, "TCGTCGTCGTCG" na leaf 0x40000000,
`hal::hypervisor::is_emulator`) valem 12 vezes mais: lá cada CPU virtual é
uma thread comum do hospedeiro, a entrega da NMI e o tratador dela passam
pela trava global do emulador, e com o hospedeiro carregado a thread de um
alvo fica segundos sem rodar, o que nada no convidado evita.
O NtFlushProcessWriteBuffers (a trava assimétrica do d3d11) é o
KeFlushProcessWriteBuffers do 19041 (`smp::flush_process_write_buffers`):
em SYNCH_LEVEL, a mesma NMI vai só aos processadores do
KPROCESS.ActiveProcessors do processo corrente, menos o corrente, e a volta
espera todos confirmarem (`smp::interrupt_processors`; com AllProcessors,
todos os APs). Interromper o alvo serializa o que ele já escreveu. O mesmo
autoteste confere que, com dois APs, só o alvo confirma.

**Frequência do TSC.** O relógio do kernel (`ke/clock.rs`) é o TSC. A
frequência vem da folha CPUID 0x15 quando ela traz o cristal e a razão;
senão é medida contra o timer de gerenciamento de energia do ACPI (o
PM_TMR_BLK do FADT, 3,579545 MHz): cada ponta de uma janela de 100 ms lê o
contador entre duas leituras do TSC e fica com o colchete mais estreito, e
vale a mediana de três janelas, então uma CPU virtual tirada de execução
pelo hospedeiro no meio da medida não a distorce. Sem o timer do ACPI, o
canal 0 do PIT da mesma forma (contagem por latch). O autoteste
(`self_test.rs`) mede de novo contra a mesma referência e exige até 0,5% de
diferença. O timer do LAPIC, que dá o quantum de 10 ms, é medido contra o
TSC da mesma forma (`nano/interrupts.rs`): três janelas one-shot de 50 ms,
vale a mediana. Com o hospedeiro carregado, uma janela única chegou a medir
o contador emulado do LAPIC 18 vezes acima do real, e o quantum e as esperas
por tempo ficavam 18 vezes mais longos.

**Relógio, fuso e QPC.** O contador de desempenho é o do HAL 19041 com o
TSC como contador (`ke/clock.rs`): KeQueryPerformanceCounter = alto(TSC ×
TscScale) + QpcBias, TscScale = 10^7 × 2^64 / frequência, 10 MHz, e o
QpcBias zera o contador no boot, então o QPC é o tempo de interrupção em
100 ns. O TSC é lido na ordem das instruções anteriores
(`cpu::rdtsc_ordered`): RDTSCP quando a CPU tem, como o
HalpTscQueryCounterOrdered, senão LFENCE (Intel) ou MFENCE (AMD) antes do
RDTSC, como o HalpTscQueryCounter com o HalpTscFenceRequired; o modo de
usuário recebe o mesmo modo nos bits de leitura do QpcBypassEnabled. Um
RDTSC sem ordem executa antes de uma leitura de memória anterior numa CPU
fora de ordem: um QPC que outra CPU publicou ficava maior que o lido
depois dele (o autoteste de monotonicidade entre o BSP e um AP falhava no
WHPX, onde o código roda no processador real; o TCG executa em ordem). A página de referência (TscSequence 'HalT', TscScale, TscOffset 0,
`mm/shared_user_data.rs`) é mapeada somente leitura em todo espaço de
endereçamento numa VA sorteada logo acima da KUSER_SHARED_DATA
((0x7FFE0 + n) << 12), que a classe 197 do NtQuerySystemInformation devolve;
com QpcBypassEnabled = 0x03 e o modo de leitura do TSC, o
RtlQueryPerformanceCounter da ntdll real lê o TSC sem syscall. As duas
páginas são `shared_user_data::shared_user_pages()`: o VAD as considera
ocupadas e a metade de usuário de um processo nunca as libera. O tick
(`clock::update_shared_times`, chamado pelos laços do kernel e pelo
`ke::timer::check_timers`) faz o KeUpdateSystemTime: InterruptTime e
SystemTime avançam em múltiplos do KeTimeIncrement corrente, as linhas de
base QPC vão junto sob o TimeUpdateLock, e o TickCount conta períodos de
KeMaximumIncrement (15,625 ms) pelo KiTickOffset; as leituras precisas
(RtlGetSystemTimePrecise, RtlGetInterruptTimePrecise) somam o QPC desde a
linha de base com o QpcSystemTimeIncrement. A interrupção do LAPIC continua
a 100 Hz (o quantum); a resolução (`ex/timer_resolution.rs`, de 156250 a
5000) só muda os passos do tempo publicado. O relógio da CMOS (`hal/rtc.rs`)
guarda a hora local: a fase 0 a toma como está, e na fase 1
`ex::time_zone::initialize` faz o que o NT faz com o CmControlVector e no
Phase1InitializationDiscard (ActiveTimeBias e RealTimeIsUniversal, a hora
do boot com o viés, o ExpRefreshTimeZoneInformation). O xtask sobe o QEMU
com `-rtc base=` na hora local do ActiveTimeBias da hive
(`cm/time_zone_information.rs`, os valores desta máquina) e compara a linha
`[time] ... UTC=` de cada boot com o relógio do hospedeiro (`*** RELOGIO`
derruba o teste com mais de 5 s de diferença).

**Pilhas de kernel por thread.** Toda thread que executa tem pilha de kernel
própria, do `mm/kernel_stack.rs` (o MmCreateKernelStack/MmDeleteKernelStack):
uma reserva fixa de 256 KB de VA na janela `KERNEL_STACK_BASE..TOP`, com a
pilha no topo (64 KB; 128 KB na grande; a reserva inteira menos a guarda na
de uma thread de kernel) em frames do PFN não contíguos, PTEs
de supervisor RW e NX, e a página logo abaixo do StackLimit sem PTE (a
guarda). `ps::process::create_kernel_thread(.., Some(pilha))` fica dono dela e
preenche os campos reais da KTHREAD do 19041: StackBase (o topo), StackLimit,
InitialStack = StackBase - 0x30 (o KERNEL_STACK_CONTROL, com CurrentStackBase
e ActualLimit) e KernelStack = InitialStack; com `None` a KTHREAD descreve a
pilha de boot (o kmain e o System rodam nela). Usam pilha própria as threads
de usuário (a primeira, da criação em `ps/create.rs`, e as de
NtCreateThreadEx), as threads de kernel (as de sistema dos drivers e os
processos de kernel do escalonador, veja abaixo), os níveis dos contextos
de KeAllocateCalloutStackEx e o segmento novo do
KeExpandKernelStackAndCallout(Ex) (`ke/callout.rs`): quando o espaço abaixo
do RSP até o StackLimit é menor que o Size pedido, ou o Size é o
KeKernelStackSize do NT (0x6000), o callout roda numa pilha nova (grande
acima de 0x6000), com a KTHREAD (InitialStack, StackBase, StackLimit) nela e
o KERNEL_STACK_CONTROL apontando o segmento anterior; a KTHREAD volta e a
pilha sai no fim. Como no KiSwapContext, o
despacho para o anel 3 (`usermode::exec_user_context`/`exec_user_mode`) grava
em KPRCB.RspBase e TSS.RSP0 a InitialStack da KTHREAD corrente: syscalls,
IRQs e exceções do anel 3 caem na pilha da própria thread, e o frame da
syscall fica logo abaixo da RspBase (`state::syscall_frame`). Fora do
intervalo as duas voltam à pilha reserva da CPU, que também serve a uma
thread sem pilha própria (o anel 3 cru dos autotestes). A pilha própria é
contada em ETHREAD.KernelStackReference, que a criação põe em 1: o ceifador
solta essa referência (`ps::process::release_kernel_stack`) e a pilha só volta
quando a última cai, depois dos PsReferenceKernelStack que a retêm
(PsDereferenceKernelStack). O ceifador roda em
`threads::release_execution_resources` para a thread de usuário morta,
o fim do contexto no escalonador para a nativa, e o fim da ETHREAD para o que
sobrar; quem libera a pilha em que a CPU ainda está a deixa para o
`kernel_stack::reap`, fora dela. A TSS do BSP leva na IST1 uma pilha própria
para a falta dupla (vetor 8): um estouro falta na guarda, a entrega da falta
não cabe na pilha estourada, e a falta dupla roda na IST e imprime
`*** ESTOURO DA PILHA DE KERNEL` com o endereço e o StackBase (a geometria
das reservas é aritmética, sem trava). IoGetStackLimits devolve StackLimit e
StackBase da thread corrente, e IoWithinStackLimits só segue o
KERNEL_STACK_CONTROL quando ele cabe no segmento. O autoteste
`ntos/test/multiprocess/kernel_stacks.rs` confere os campos e a guarda, uma
syscall de teste cujo RSP fica entre o StackLimit e o InitialStack da thread
(distinto entre duas threads, com RspBase e RSP0 iguais à InitialStack
durante a syscall), o IoGetStackLimits de uma thread nativa, o PFN estável
depois de criar e destruir 8 threads, a IST1 da falta dupla e as pilhas de
callout.

**Threads de kernel.** Toda thread de kernel — as threads de sistema dos
drivers (PsCreateSystemThread, `ps/kernel_threads.rs`), os processos de
kernel do escalonador (o serviço de teclado, o shell, os dos autotestes) e as
requisições do kernel com thread própria — tem KTHREAD com pilha de kernel
própria (`kernel_stack::create_for_kernel_thread`: a reserva inteira menos a
guarda, porque os serviços do kernel que o código nativo chama rodam nela) e
roda inteira nela. O tick do escalonador (`ps/scheduler.rs`), que roda no
despachante da CPU — o contexto de boot, nunca a pilha de uma thread de
kernel —, escolhe pelas filas de prioridade e entra na thread por uma troca
de contexto (`context_switch::resume`, com o quadro de troca salvo em
KTHREAD.KernelStack; a primitiva simétrica é `hal/amd64/context_switch.rs::
swap`, e uma thread nova recebe um quadro inicial que entra na rotina dela);
a thread devolve a CPU por outra troca (`switch_out`) ao ceder a vez, ao
esperar ou ao terminar. Cada lado da troca leva o seu estado da CPU: o IRQL
(KTHREAD.WaitIrql numa espera), as chamadas nativas em curso, as posses de
SharedLock (o `rtl::sync::SharedLock` é da thread, não do processador) e a
thread corrente com a raiz do processo dela. A rotina de uma thread de
sistema roda pelo caminho síncrono dos exports, como o DriverEntry: cada API
que o código nativo chama é servida na pilha da própria thread (as chamadas
em curso, `rtl/native_context.rs`, são achadas pela pilha, não pela CPU); na
entrada de cada export, uma thread que gastou o quantum (KTHREAD.CycleTime
alcançou o QuantumTarget, como no KiQuantumEnd) cede a vez antes do serviço
e recebe as APCs de kernel pendentes. As chamadas nativas em curso são da
thread (`hal/amd64/native_call.rs`): o contexto nativo agendado em execução
(o `run_kernel_context` dos handlers e funclets de SEH, cujo código sai para
o hospedeiro a cada export) e a posse de execução nativa síncrona (só faltas
numa execução possuída entram no SEH de kernel) são duas células da CPU na
reserva da KPCR, que os trampolins leem por `gs:` e a troca de thread leva
com a thread que sai; o RSP do hospedeiro para onde a saída de um contexto
agendado volta fica no próprio quadro dele. Duas threads que se intercalam
dentro de chamadas nativas, ou duas CPUs ao mesmo tempo, nunca veem o
estado uma da outra (uma célula única do sistema mandaria o export de um AP
para a saída do contexto do BSP, pela pilha do hospedeiro dele). O autoteste
`ntos/test/multiprocess/native_interleave.rs` intercala duas threads de
sistema dentro dos próprios contextos agendados, por eventos esperados de
dentro deles, e faz um AP chamar um export enquanto o BSP está num contexto
agendado. A rotina que retorna termina a thread,
e o PsTerminateSystemThread termina de dentro do serviço pela última troca.
Como no PsCreateSystemThreadEx do 19041, o handle da thread é sempre de
kernel (OBJ_KERNEL_HANDLE ligado nos atributos do chamador). Sem
ProcessHandle a thread é do System. Com ele, o ObReferenceObjectByHandle
(PROCESS_CREATE_THREAD, KernelMode) escolhe o processo da thread, e a recusa
é o status devolvido. A thread de modo kernel roda então com a raiz desse
processo e vê o espaço de sessão dele: o cdd.dll cria assim a thread de
apresentação (PresentWorkerThread) no csrss da sessão. O autoteste
`ntos/test/multiprocess/attach_cr3.rs` cria a thread num processo com
espaço próprio e confere que ela lê a página do espaço dele pela VA de
usuário.
Pedido de dentro de uma thread de kernel (o pump de uma espera genérica, o
ZwYieldExecution com outra pronta, um SharedLock disputado), o tick não
aninha: a thread cede a vez. Um SharedLock disputado num AP não roda o tick:
o AP executa trabalhos sem thread corrente, como o código do NT sem thread
que possa esperar (a ociosa, uma DPC), e gira até o dono soltar; o tick lá
venceria timers e despacharia processos ao mesmo tempo que o BSP
(`ntos/test/multiprocess/contention.rs`). Uma thread em execução dada como pronta
(`thread_dispatch::make_ready`) continua fora da fila, e o despachante a
recoloca no fim do passo. A espera de uma thread de kernel (`ke/wait.rs`, o
KiCommitThreadWait do 19041) tira a thread das prontas e troca de contexto;
cada objeto esperado recebe um KWAIT_BLOCK da KTHREAD (WaitBlock[0..3), ou um
vetor do pool acima de três) ligado à DISPATCHER_HEADER.WaitListHead, com
WaitType (WaitAll 0, WaitAny 1, WaitNotification 2, WaitDequeue 3),
BlockState e WaitKey; o prazo arma o KTIMER da thread (KTHREAD.Timer) com o
WaitBlock[3] e a chave STATUS_TIMEOUT; a KTHREAD publica State Waiting,
WaitReason, WaitMode, Alertable, WaitBlockList, WaitBlockCount e o
KWAIT_STATUS_REGISTER (WaitInProgress até o despachante confirmar a saída da
CPU, WaitCommitted depois; uma saída antes disso a marca WaitAborted e a
thread volta direto à fila). O despachante confirma a espera só depois de a
thread sair da execução como Waiting (`scheduler::run_step`). Na ordem
inversa, um sinal de outra CPU no intervalo aprontaria a thread ainda em
execução, e o Waiting gravado depois a perderia. O KTHREAD.State de uma
thread de kernel do escalonador só muda pelo despachante: Running ao
retomá-la, Waiting na troca da espera, Ready pelo KiReadyThread do
KiUnwaitThread. A espera de alertas (`ke/thread_alert.rs`), que as retiradas
de porta de conclusão e as esperas sondadas armam, não grava esse State. O
fim dela pode vir de outra thread: a reserva de pacotes da porta roda no
contexto de quem publica. Um Running restaurado ali marcava a thread parada
fora da CPU como Running, o KiReadyThread a pulava e ela nunca mais era
escolhida (a thread de trabalho do msrpc.sys no RegisterLogonProcess do
winlogon). Quem apronta é o sinal (o KiWaitTest,
`wait::signal`): KeSetEvent, KePulseEvent, KeReleaseSemaphore,
KeReleaseMutex, o vencimento de um timer (o tick vence os timers devidos,
como a interrupção de relógio), o fim de uma thread ou de um processo
satisfazem os blocos consumindo pela thread que espera (o evento de
sincronização, a permissão do semáforo, a posse do mutant; o WaitAll só com
todos disponíveis), e a saída da espera (o KiUnwaitThread) desliga os blocos,
cancela o timer, grava KTHREAD.WaitStatus e põe a thread na fila pronta. A
thread que sai da espera entra na fila com o ajuste de prioridade do
KiDeferredReadySingleThread do 19041 (o ramo AdjustUnwait,
`thread_dispatch::ready_after_wait`, sob a ThreadLock e o PrcbLock): o sinal
leva o incremento dele, o Increment do KeSetEvent, KePulseEvent,
KeReleaseSemaphore, KeReleaseMutant e KeInsertQueueApc dos drivers; 1 no
NtSetEvent, NtPulseEvent, NtReleaseSemaphore, NtReleaseMutant,
NtSignalAndWaitForSingleObject, KeReleaseMutex, NtAlertThreadByThreadId e na
entrega ALPC (o AlpcpSignal; aqui todas as threads que vigiam o transporte
acordam, não só a destinatária); 2 no KeAlertThread; zero no vencimento de um
timer (o KiTimerWaitTest) e nos sinais internos do kernel. Abaixo de 16, a
prioridade vai a Base + incremento, mais o PsPrioritySeparation num processo
de primeiro plano (MemoryPriority 2 no working set; essa parte fica no
ForegroundBoost), até 15, quando isso a sobe. Com o quantum gasto, com a base
em 14 ou mais ou depois de uma espera de dois ticks do 19041 (32 ms) ou mais
sem impulso em curso, a prioridade antes decai como no fim de quantum e o
quantum renova; com DisableBoost, com um impulso incomum em curso ou com o
quantum gasto numa espera curta, não sobe. O fim de quantum desfaz o impulso
aos poucos (o KiComputeNewPriority). O autoteste `ntos/test/unwait_boost.rs`
(fase 6) para uma thread de sistema num evento, grava na KTHREAD dela cada
combinação (base, prioridade, impulso em curso, DisableBoost, espera curta ou
longa, quantum gasto, processo de primeiro plano) e confere a prioridade, o
PriorityDecrement e o quantum com que o KeSetEvent ou o KeAlertThread a põe
na fila. O
KeInsertQueue entrega a entrada direto à thread mais recente parada na fila
(o KiInsertQueue: o bloco WaitDequeue com WrQueue entra na cabeça da
WaitListHead; com vaga livre e quem insere fora da fila, a entrada não passa
pela lista e a thread sai da espera ocupando a vaga). Um alerta numa espera
alertável sai com STATUS_ALERTED; uma APC de usuário numa espera alertável
de UserMode, com STATUS_USER_APC; uma APC de kernel numa espera em
PASSIVE_LEVEL, com STATUS_KERNEL_APC (a thread a entrega e espera de novo
pelo prazo restante). A conclusão de uma requisição de arquivo, que só
termina no contexto de quem pediu (o papel da APC especial do
IopCompleteRequest), tira da espera da mesma forma a thread de kernel que
pediu; uma APC de kernel para uma thread numa espera sondada a põe de volta
na fila para entregá-la na própria pilha. Numa thread de usuário parada
num serviço (o RIT do win32k no KeWaitForMultipleObjects, com o ZwReadFile
assíncrono do RIMStartDeviceRead pendente no kbdclass ou no mouclass), essa
conclusão e a APC da ApcRoutine que ela enfileira são drenadas no contexto
da thread pelo despachante de usuário (`drain_kernel_apcs`). Os locks do Ex (fast e guarded mutex, ERESOURCE, push
lock, rundown, `context_switch::acquire_signaled`) esperam com um bloco de
notificação no evento em que a requisição estacionou (o Event do FAST_MUTEX,
o WakeEvent do bloco do push lock e do rundown, o evento do bloco do
ERESOURCE): o KeSetEvent de quem solta acorda a thread, que confere a palavra
de novo, como o laço do ExpAcquireFastMutexContended. Todo ERESOURCE fica
na SystemResourcesList desde o ExInitializeResourceLite, e o
ExDeleteResourceLite o tira dela mesmo com dono ou espera, zerando os
vínculos, como o ntoskrnl (rva 0x275720): o ntfs.sys apaga assim a tabela de
reinício do NtfsCheckpointVolume, dois ERESOURCE na pilha dele, com o
primeiro ainda adquirido, e um recurso de pilha esquecido na lista faria as
inserções e remoções seguintes gravarem na pilha de outra chamada (o
autoteste `eresource_deleted_while_owned`, na fase 6). A retirada de uma porta
de conclusão (ZwRemoveIoCompletion[Ex]) e as esperas do ALPC
(`alpc::kernel_entry::wait_transport`: a recepção, a conexão, a resposta de
um pedido síncrono) são esperas explícitas (`wait::wait_woken`): a entrega dos
pacotes pela porta, uma mensagem na fila de uma porta, um pedido, uma
resposta, a decisão de uma conexão ou o fecho de uma porta aprontam a thread
(`wait::wake`), que sonda a operação de novo. A porta de conclusão também é
um objeto de espera comum: o corpo do IoCompletion é uma KQUEUE
(`ob/objects/completion.rs`, SignalState = pacotes na fila, CurrentCount e
MaximumCount da concorrência), e uma KQUEUE com entradas satisfaz o
KeWaitForSingleObject/Multiple sem consumir (`dispatcher::acquire_status`);
a fila que ganha pacotes, e o KeInsertQueue que deixa a entrada na lista,
testam as esperas do cabeçalho. O win32k espera assim a porta da fila de
mensagens de cada thread GUI (o pacote de espera do evento da fila a
alimenta). Como o bloco de notificação do KeRegisterObjectNotification, o
pacote de espera sobre um evento ou um semáforo vai para a fila dentro do
próprio sinal (`wait::signal` chama o observador de
`ps/user/wait_packets.rs`): depois do KeSetEvent do SetWakeBit, ou de um
KePulseEvent, a consulta da porta com prazo zero (o atalho do
NtUserPeekMessage, o NtUserMsgWaitForMultipleObjectsEx com dwTimeout 0) já
vê o pacote; os demais alvos, e o sinal em DISPATCH_LEVEL ou com um
SpinLock retido, ficam com o pump do despachante. As demais esperas genéricas de
uma condição sem objeto a sinalizar (`context_switch::wait_until`, como a
remoção de um callback à espera do fim das chamadas em curso) tiram a thread
das prontas com a condição sondada pelo despachante a cada tick
(`scheduler::block_polled`). As listas e os registros das esperas ficam sob o
lock do despachante (`wait::lock`), o mesmo do estado das filas. O
contexto de boot, que é o próprio despachante da CPU, espera girando o
`pump_kernel` (interrupções de dispositivo abaixo de DISPATCH_LEVEL, timers,
DPCs, o gerenciador das worker threads e o tick, que entra nas threads de
kernel, as workers dos work items inclusive). O autoteste
`ntos/test/kernel_waits.rs` (fase 6) roda duas threads de sistema em
pingue-pongue por dois eventos e por duas KQUEUE (a parada tem o bloco na
WaitListHead, fica Waiting e não gasta ciclo nem troca de contexto enquanto o
sistema gira; o sinal a apronta na hora; o KeInsertQueue entrega a entrada
direto, com a lista vazia e a vaga ocupada), um servidor e um cliente ALPC
de kernel em threads de sistema e um processo de kernel em execução dado como
pronto, que segue fora da fila e espera um prazo sem gastar CPU: pela
contabilidade da própria thread, o KTHREAD.CycleTime não muda em nenhuma das
amostras tiradas enquanto ela está Waiting e ela é despachada uma única vez
(a que a acorda), o que a carga do hospedeiro não altera. O mesmo autoteste
põe duas threads de sistema a repetir o ZwRemoveIoCompletionEx numa porta de
conclusão, e depois o KeRemoveQueueEx numa KQUEUE, com uma terceira thread a
publicar dois pacotes por rodada. Cada pacote chega a uma consumidora já
parada, que sai da espera Ready, e as 129 entregas chegam sem nenhuma
consumidora perdida.

**Esperas que bloqueiam.** Uma thread de usuário que espera dentro de uma
syscall deixa a CPU, como no KiSwapContext do NT, em vez de girar o
`pump_kernel` com o despachante parado. A decisão fica em
`ke/context_switch.rs`: `can_block` exige a thread de usuário da syscall
despachada nesta CPU (qualquer uma que despacha), rodando na própria pilha de kernel e
sendo a execução em curso do `thread_dispatch` (nada aninhado: um passo do
escalonador, uma APC drenada em nome de outra thread), IRQL abaixo de
DISPATCH_LEVEL e nenhum SpinLock nem SharedLock retido — cada CPU conta as
posses dos dois (`rtl/sync.rs`) em células da sua reserva de KPCR, pelo GS.
`block_current` instala na `UserThread` uma espera cuja sondagem é a da
própria espera (emprestada da pilha da thread), marca o serviço suspenso
(`KernelState::Blocked`), guarda a IRQL em KTHREAD.WaitIrql e chama a
primitiva de `hal/amd64/context_switch.rs`: o quadro de troca (rbx, rbp,
rdi, rsi, r12-r15, RFLAGS, xmm6-xmm15, MXCSR e a palavra de controle x87, a
união das convenções do kernel e MS x64) fica na pilha da thread, o RSP vai
para KTHREAD.KernelStack, e a CPU sai pelo fim do intervalo
(`user_terminate_current`) com o tipo de saída 4; a thread leva na pilha o
estado por CPU do serviço (CONTEXT do intervalo, quadro e faixas preservadas
da syscall, KPCR.UserRsp, NtContinue, chamadas nativas em curso). O
despachante de `ps/user/threads.rs` segue com as outras threads, sonda a
espera no contexto da bloqueada (thread corrente e CR3 dela) e, quando ela
conclui, retoma o
serviço na pilha dela (`switch_to` → `usermode::resume_kernel_context`, que
monta um quadro de despachante novo e entra no quadro salvo) em vez de entrar
no anel 3; a syscall retomada sai como qualquer outra (direto ao anel 3,
quando nada pede o despachante). Passam por aí
KeWaitForSingleObject/Multiple (alertáveis ou não), KeDelayExecutionThread,
fast/guarded mutex, ERESOURCE, push locks e rundown
(`context_switch::wait_until`/`acquire_until`), KeRemoveQueue/
KeRemoveQueueEx (`ke/queue.rs`: a entrada disponível vence o alerta; prazo,
alerta e APC de usuário na alertável devolvem o status e a thread volta a
ocupar a vaga) e as esperas de conclusão de E/S: a E/S síncrona de
NtReadFile, NtWriteFile e ZwDeviceIoControlFile (`io/file/request.rs::
wait_finished`, o evento do FILE_OBJECT do IopSynchronousServiceTail,
alertável com FO_ALERTABLE_IO; interrompida por alerta, APC de usuário ou
término da thread, cancela o IRP e espera a conclusão sem alerta), o IRP
retido com evento de conclusão, a saída de thread com E/S pendente e o
ZwRemoveIoCompletionEx. O despachante sonda a espera da bloqueada no
contexto dela e roda o `pump_kernel`, com as interrupções de dispositivo
abaixo de DISPATCH_LEVEL (`interrupt_object::service_during_wait`), a cada
volta; as threads de kernel esperam como descrito acima, e só o contexto de
boot (com as APCs e conclusões drenadas por ele) continua girando o pump.
Como no NT, esperar de fato com prazo não nulo em
DISPATCH_LEVEL ou acima, ou com um SpinLock retido, para o sistema (assert).
Uma thread sem estado do win32k terminada enquanto bloqueada tem a espera
concluída com STATUS_THREAD_IS_TERMINATING e é retomada para desfazer o
serviço antes de a pilha voltar ao Mm (uma aquisição continua até concluir,
como a espera de um mutex no NT); o término de um processo espera as threads
dele desfazerem os serviços. Uma thread com estado do win32k
(KTHREAD.Win32Thread) termina como no 19041 (o PspTerminateThreadByPointer e
o KeRequestTerminationThread, `threads::request_termination`): o pedido marca
CrossThreadFlags.Terminated, ETHREAD.ExitStatus do primeiro pedido,
KTHREAD.ThreadFlags.TerminationApcRequest e UserApcPending (no NT a
SchedulerApc vira a APC de usuário do KiSchedulerApcTerminate, que o
KiInsertQueueApc põe na cabeça da fila com UserApcPending), alerta a thread
em KernelMode e zera a suspensão. Nenhuma espera é concluída de fora: a de
UserMode, alertável ou não, sai com STATUS_USER_APC (o KiCheckAlertability,
que o caminho sondado dos KeWaitFor*, do KeDelayExecutionThread e do
KeRemoveQueueEx agora segue também nas não alertáveis), a alertável de
KernelMode sai com STATUS_ALERTED, a não alertável de KernelMode continua até
concluir, e as esperas de E/S que conferem o Terminated cancelam o pedido. O
serviço se desfaz e, na volta ao modo usuário, a thread roda o próprio
PspExitThread (`threads::exit_current`), na pilha dela, num intervalo de
serviço (pode bloquear), com o Win32Thread ainda publicado: no fim da syscall
(`threads::service_exit_termination`, o KiServiceExit), na volta ao anel 3 de
um callback, ou, se ela estava no anel 3, num intervalo que roda a rotina de
kernel em vez de entrar no anel 3 (`usermode::exec_kernel_routine`, o
KiSchedulerApcTerminate; a saída do intervalo é EXIT_THREAD_EXITED). Ali saem,
na ordem do PspExitThread, as notificações e o callout de saída de thread do
win32k (antes das rotinas de E/S, timers, notificações do Cm e mutantes), o
rundown das APCs, o token, a contagem no EPROCESS e o objeto thread
sinalizado; a última thread viva do processo conclui o fim dele ali mesmo,
com o callout de saída de processo antes das notificações de processo. É
por esse callout que o shell volta quando o explorer.exe cai: o
DestroyProcessInfo do win32kbase (0x46f60) vê que o processo é o shell da
Desktop de entrada (o ppiShellProcess que o SetShellWindow pôs no
DESKTOPINFO, numa WindowStation com E/S) e lê o código de saída pelo
PsGetProcessExitStatus; diferente de 1 e de 0xff (o explorer que sai pelo
CTray::_DoExitExplorer usa 1 e não é recriado, como o `taskkill /f`), o
PostWinlogonMessage(0x401, código) vai pelo RPC assíncrono do kernel
(msrpc.sys) ao endpoint `WMsgKRpc<luid><sessão>` que o winlogon registrou
e o RegisterLogonProcess ligou (WmsgpConnect). O WMsgKMessageHandler do
winlogon liga o sinal Winsrv_ShellRestart (0xa), e o
WLGeneric_ShellRestart_Enter lê o AutoRestartShell (1 sem o valor) e o
Shell de Winlogon e cria o explorer.exe na Winsta0\Default com o token do
usuário (teste reinicio-do-shell). Os
serviços Nt* que
esperam por handle (NtWaitFor*, NtDelayExecution) continuam com o modelo
PENDING, sem pilha suspensa, com a espera registrada no despachante (abaixo). O NtWaitForSingleObject e o
NtWaitForMultipleObjects de modo usuário capturam o prazo e os handles e
resolvem os objetos pelo mesmo `ob/wait::reference_objects` do
ObWaitForMultipleObjects (tabela nativa, tabela de usuário, SYNCHRONIZE em
UserMode): o objeto de espera é o DefaultObject do tipo (o corpo dos tipos
com DISPATCHER_HEADER, o FILE_OBJECT.Event, a KQUEUE do IoCompletion, que o
WaitAll recusa com STATUS_INVALID_HANDLE) e, nos demais tipos, o
ObpDefaultObject (um evento de notificação sempre sinalizado); Count fora de
1..64 dá STATUS_INVALID_PARAMETER_1, WaitType além de WaitAny
STATUS_INVALID_PARAMETER_3, e um objeto repetido só é recusado no WaitAll
(STATUS_INVALID_PARAMETER_MIX). Os prazos dessas esperas contam em
ms arredondados para cima (um prazo não nulo abaixo de 1 ms espera o
próximo ms, nunca vence de imediato). Uma espera sondada (a do contexto de
boot, a associação de um pacote de espera) não tem bloco na
WaitListHead, e o KePulseEvent sinaliza e limpa o evento antes de qualquer
sondagem: o pulso que acha o evento não sinalizado fica anotado
(`dispatcher::PolledObjects`, na contagem global de pulsos), e a espera
WaitAny que começou antes dele (a associação de um pacote de espera guarda
a contagem de pulsos de quando foi feita) é satisfeita por ele como o
KiTryUnwaitThread do KePulseEvent satisfaz a registrada: todas num evento de notificação, uma por pulso num de
sincronização cujo sinal nenhuma espera consumiu. O WaitAll não conta
pulsos. Do mesmo jeito, o KeResetEvent e o KeClearEvent de um evento
sinalizado (19041 0x344c50: só zeram o SignalState, e as esperas que o
KeSetEvent já tinha satisfeito continuam satisfeitas) e o KeSetTimer que
rearma um KTIMER ou KTIMER2 vencido anotam um pulso: a espera sondada que
já esperava quando o objeto foi sinalizado conclui mesmo com o reset antes
da sondagem dela, e a que começa depois do reset não.

**Esperas registradas das threads de usuário.** As esperas de objeto, de
prazo e de alerta das threads de usuário passam pelos blocos de espera do
despachante (`ke/wait.rs`), como as das threads de kernel, em vez de serem
sondadas a cada volta do despachante de usuário. Dentro de um serviço
bloqueado no kernel (os KeWaitFor*, o KeDelayExecutionThread, o
fast/guarded mutex, o ERESOURCE, o push lock e o rundown, pelo
`acquire_signaled`), o laço do `ke::wait` liga os KWAIT_BLOCKs e a thread
deixa a CPU com o serviço suspenso (`context_switch::block_registered`); a
APC de kernel interrompe a espera em PASSIVE_LEVEL, a thread a entrega e
espera de novo, como o KeWaitForSingleObject do NT. Num serviço de UserMode
que devolve STATUS_PENDING (o NtWaitForSingleObject, o
NtWaitForMultipleObjects, o NtSignalAndWaitForSingleObject, o
NtDelayExecution, a espera do `cm/notify.rs`), `threads::wait_registered`
tenta os objetos, confere os alertas e a APC de usuário pendente (o
KiCheckAlertability) e o prazo zero, e instala a espera sem ligar nada: os
blocos só são ligados quando a thread deixa a CPU (`threads::execute`,
`wait::begin_user_wait`, com a tentativa de novo sob o lock), depois de todo
o código do serviço. O que o serviço ainda faz depois de instalar a espera
(soltar referências, um lock do Ex contendido, um KeWaitFor*) registra e
desfaz as esperas dele sem achar os blocos embutidos da KTHREAD já ligados
(o `link_wait` recusa religar os de uma espera ainda ligada). A APC de
kernel não interrompe essa espera, que o despachante conclui no contexto
da thread. Ligada a espera, o despacho de usuário põe a thread Waiting e a
confirma (`wait::commit_user_wait`, o KiCommitThreadWait, depois do
`end_execution`, como o `run_step` das threads de kernel); um alerta ou uma
APC de usuário que chegou com a espera em curso a desfaz, e a espera já
satisfeita no registro volta direto à fila. O sinal (KeSetEvent, KePulseEvent, KeReleaseSemaphore, o
mutant, o timer da thread no prazo, o fim de uma thread ou processo) desfaz
a espera e apronta a thread dentro dele (o KiUnwaitThread -> KiReadyThread);
o despachante só leva o KTHREAD.WaitStatus ao CONTEXT (ou à retomada do
serviço bloqueado) ao escolhê-la, sem sondar nada e sem carregar o CR3
dela. Uma thread aprontada assim que está suspensa volta a esperar até a
retomada. O término e o fim do processo desligam os blocos com
STATUS_THREAD_IS_TERMINATING, e o pedido de término do 19041 tira a espera
registrada de UserMode com STATUS_USER_APC (`wait::user_apc_published`).
Os blocos embutidos (KTHREAD.WaitBlock[0..3]) recebem só os campos que o
KiWaitMultiple grava: o SpareLong e o SparePtr deles são outros campos da
KTHREAD na mesma memória (ContextSwitches, State/WaitIrql/WaitMode,
WaitTime, ThreadCounters, XStateSave, o Win32Thread no SparePtr do
WaitBlock[2], Ucb/Uch). O teste das esperas de um objeto (o KiWaitTest,
`DispatcherLock::wait_test`) segue para o próximo bloco de outra thread: os
seguintes da mesma thread na mesma lista (um WaitAny no mesmo objeto duas
vezes) saem com ela no `unwait`, e o vínculo de um bloco desligado aponta
para ele mesmo. As esperas acordadas (`threads::Registered::woken`)
são as de uma condição que não é o estado de um objeto: o
NtWaitForAlertByThreadId (o NtAlertThreadByThreadId a acorda pelo
`wait::wake`, como o KeAlertThreadByThreadId), a retirada de uma porta de
conclusão e a espera de trabalho da worker factory (um bloco de notificação
na KQUEUE da porta, que o pacote novo, a vaga de concorrência liberada, o
consumidor que saiu, o fechamento, o encerramento da fábrica e o pedido da
classe 12 sinalizam; o timer da espera vence também no fim da ociosidade do
worker) e as esperas do transporte ALPC/LPC (o `notify_waiters` de toda
mudança do transporte, como para as threads de kernel). A saída de uma
acordada só faz a sondagem dela rodar, no contexto da thread; sem
conclusão, os blocos são ligados de novo. Uma acordada sem saída é sondada
mesmo assim a cada 50 ms (`WOKEN_BACKSTOP_MS`). As demais esperas de
serviço (a E/S de dispositivo, as condições próprias de um serviço e os
`context_switch::wait_until` sem objeto) seguem sondadas a cada volta.
Autoteste: `ntos/test/multiprocess/registered_wait.rs` (a thread pronta
dentro do KeSetEvent, nenhuma espera sondada, o KeWaitForSingleObject
dentro do serviço, a espera adiada seguida de um lock contendido no mesmo
serviço, o WaitAny com o mesmo evento duas vezes, a suspensa, o alerta por
id, o atraso, o fim do processo sem bloco na WaitListHead e os campos
sobrepostos intactos). O NtDelayExecution com intervalo zero,
sem Alertable e sem UserApcPending, é a troca do NtYieldExecution
(STATUS_SUCCESS ou STATUS_NO_YIELD_PERFORMED), como no
KeDelayExecutionThread. Os dois e o ZwYieldExecution escolhem como o
KeYieldExecution(0) (`thread_dispatch::request_yield_execution`, o
KiSelectReadyThreadEx(Prcb, NULL, 1)): a NextThread ou a pronta de maior
prioridade a partir de 1, de qualquer prioridade relativa à da thread que
cede; no fim da execução a prioridade de quem cede recebe o ajuste do fim
de quantum e uma sucessora de prioridade menor fica reservada na
NextThread, sem perder para a thread que cedeu (teste:
`ntos/test/yield_execution.rs`). A cessão de uma thread de kernel no
próprio laço do escalonador segue só para uma pronta de prioridade igual ou
maior. O NtSignalAndWaitForSingleObject referencia o
objeto a sinalizar sem direito e o de espera com SYNCHRONIZE, sinaliza pelo
tipo (`ob/wait::SignalObject`: evento com EVENT_MODIFY_STATE, mutant com a
posse, semáforo com SEMAPHORE_MODIFY_STATE e o limite, outro tipo
STATUS_OBJECT_TYPE_MISMATCH) e só então espera; a CPU de usuário é do
serviço até a espera ser instalada, então o par é atômico. O
NtAlertThreadByThreadId recusa a thread de outro processo (o KTHREAD.Process
dela contra o da corrente) com STATUS_ACCESS_DENIED, sem deixar o alerta
pendente. As esperas de modo usuário gravam na KTHREAD o que o
KiCommitThreadWait grava (WaitMode UserMode, Alertable, WaitReason e
WaitTime; o State Waiting vem do despacho): WrAlertByThreadId,
DelayExecution, WrQueue (portas de conclusão e worker factory),
UserRequest (esperas de objeto) ou Executive; o SystemProcessInformation
dá o ThreadState e o WaitReason da KTHREAD. A APC especial de usuário
entra no começo da lista de usuário (o KiInsertQueueApc): sai antes das
normais e, entre as especiais, a mais nova primeiro. O autoteste
`ntos/test/multiprocess/blocking_wait.rs` roda duas threads de um processo
real no despachante: a 1 espera um KEVENT sem prazo numa syscall de teste e
a 2, que só fica pronta depois disso, a vê bloqueada (Waiting, KernelStack
dentro da pilha dela) e sinaliza o evento; a 1 volta na própria pilha com
STATUS_SUCCESS e devolve 0 ao anel 3. Um segundo cenário termina a thread
bloqueada (THREAD_IS_TERMINATING, desfeita na própria pilha). Dois cenários
terminam uma thread com Win32Thread (um bloco do teste): bloqueada numa
espera não alertável de UserMode, como a do xxxRealSleepThread do win32kfull,
o NtTerminateThread da outra só pede o término (ela segue viva, com
Terminated e TerminationApcRequest), a espera sai com STATUS_USER_APC na
pilha dela e ela sai no fim do serviço sem voltar ao anel 3; girando no anel
3, ela sai pelo intervalo sem anel 3. Nos dois, uma rotina de saída de thread
do teste vê a thread corrente, na própria pilha de kernel, num intervalo de
serviço e com o Win32Thread publicado. O autoteste
`ntos/test/multiprocess/queue_wait.rs` faz o mesmo com o KeRemoveQueue: a
thread que espera na fila fica parada (CycleTime constante) enquanto a
outra gira 50 ms e insere, e volta com a entrada; com prazo de 100 ms e
ninguém inserindo, volta com STATUS_TIMEOUT sem gastar a espera em ciclos;
no KeRemoveQueueEx alertável em UserMode, o NtAlertThread da outra a
interrompe com STATUS_ALERTED; nos três a vaga da fila volta.

**Despachante de todos os processos.** Um despachante só serve as threads
de usuário de todos os processos vivos (`ps/user/threads.rs`):
`dispatch_one` roda o trabalho do despachante sem o tick do escalonador
(`dispatcher::pump_kernel_work`: as interrupções de dispositivo adiadas, os
timers, as DPCs, o gerenciador das worker threads e as conclusões
registradas) e os pumps de ALPC, `device_io`,
fábricas e pacotes de espera, sonda depois deles as esperas de todas as
threads dos processos que entraram nele (`ProcessState.started`), retoma as threads
terminadas que precisam desfazer um serviço bloqueado, conclui os términos
adiados e dá um intervalo à thread de usuário pronta mais prioritária da
fila do `thread_dispatch`, de qualquer processo; a troca de thread corrente
carrega a raiz do processo dela. A sondagem vai pela prioridade e, na mesma
prioridade, pelo processo: sem PCID nem páginas globais, cada carga de CR3
esvazia o TLB, também o do kernel; um NtDelayExecution já sondado se decide
sem o contexto da thread (o alerta e as APCs são conferidos pelo ponteiro
dela). O tique começa pelo `dispatch_one`, então os pumps e os fins de
processo adiados andam a cada tique mesmo sem thread de usuário pronta (a
criação adiada de um worker de uma fábrica, a nova tentativa dela, o pedido
a um servidor de kernel); quando um intervalo deixa a fila vazia, ele
chama o `dispatch_one` de novo, que sonda uma vez e já dá o intervalo à
thread que o anterior acordou (um envio e espera ALPC, a resposta adiada de
uma fábrica, o KeSetEvent de uma thread de kernel), como o KiUnwaitThread
do 19041 a apronta dentro do sinal, em vez de esperar o próximo tique de
10 ms. Os contadores do despachante (`ps/dispatch_perf.rs`: o tempo no HLT
e no giro do laço ocioso, nas sondagens, com as esperas sondadas e as
cargas de CR3, e no despacho fora dos intervalos) saem na serial a cada
5 s como linhas `[perf]`, e o xtask anota em cada uma a hora do hospedeiro
(`[xtask] [perf] aos N s`). Até a tela de logon eram duas sondagens por
intervalo, e elas chegavam a 40% do tempo da CPU. O autoteste
`ntos/test/multiprocess/polled_wake.rs` põe duas threads de usuário em
pingue-pongue por dois eventos dentro de serviços de teste e conta as
voltas num número fixo de tiques. O despacho roda dentro do tick, que já
alterna os passos das threads de kernel e os intervalos de usuário pela
prioridade: antes, o `pump_kernel` dele aninhava um tick a cada 2 ms, que
rodava as threads de kernel fora da prioridade delas e contava o tempo delas
como despacho de usuário. Quem despacha fora do tick (o contexto de boot em
`threads::wait_for_process`, os autotestes) usa `threads::dispatch_round`,
o despacho e os passos de kernel do tick (`scheduler::tick(0)`). A sondagem
das esperas de usuário só roda quando tem o que achar: a época de despertar
andou ou passou um tique do relógio desde a anterior (`threads::poll_due`).
As esperas registradas ficam prontas no próprio sinal; o tique cobre o
prazo das esperas que ainda são sondadas, a sondagem de garantia das
acordadas e uma condição que mude sem sinal, com no máximo um tique de
atraso. A linha `[perf]` separa, no despacho fora dos intervalos, os pumps
e os fins de processo, conta as sondagens dispensadas e mostra o tempo dos
passos das threads de kernel. O autoteste
`ntos/test/multiprocess/dispatch_overhead.rs` confere que o `dispatch_one`
com uma thread de sistema pronta não a roda e o `dispatch_round` a roda, e
que, no mesmo tique e sem despertar, as sondagens seguidas são dispensadas e
um despertar ou o tique seguinte as fazem rodar.

A saída de um serviço é a do KiSystemServiceExit do 19041 (0x411510; a
opção de boot `--slow-service-exit`, SLOWSERVICEEXIT, a desliga para isolar
um problema nela, e o `--fast-service-exit` de antes é aceito sem efeito): sem
troca de thread a fazer, ela volta direto ao anel 3 pelo `user_syscall_exit`
do stub e o intervalo segue (`usermode::continues_in_interval`). O 19041
não testa o escalonador ali, porque a troca, quando era preciso, já
aconteceu dentro do serviço; aqui, sem preempção dentro do serviço,
`threads::may_return_to_user` pergunta, e o intervalo acaba como antes (o
CONTEXT e o despachante) quando o intervalo não é do despachante, quando a
thread está num callback de modo usuário, fora de PASSIVE_LEVEL, anexada
ou com trava retida, quando instalou uma espera ou está bloqueada, morta,
suspensa, terminando ou com exceção pendente, quando tem APC de usuário
(a de término inclusive), APC de kernel ou conclusão de E/S, quando pediu
para ceder a CPU, quando outra thread deve tomá-la (uma reserva ou uma
pronta estritamente acima, a regra do KiReadyThread), quando um tique
passou desde o começo do intervalo (o quantum é do tique), quando há DPC ou
IRQ de dispositivo por atender, quando o serviço precisa do CONTEXT
(NtContinue, o callback de instrumentação, as faixas gravadas pelo
SetContext e pelos registradores de depuração), quando o depurador armou
um passo e quando algo pode ter concluído uma espera sondada desde a última
sondagem (as registradas no despachante ficam prontas no próprio sinal, e a
pronta acima da corrente já pede a troca): a época de despertar (`dispatcher::wake_epoch`) anda no sinal de
um objeto, num pulso ou no reset de um objeto sinalizado, na entrega a uma
KQUEUE, a uma porta de conclusão ou a uma porta ALPC, numa APC, num alerta,
num IRP concluído e na retomada ou no término pedido de uma thread, e a
sondagem guarda a época de quando começou. Antes, todo serviço acabava o
intervalo e custava uma passada do despachante (0,1 a 0,36 ms); o thread de
interface do LogonUI, que faz uma espera de prazo zero em cada comparação
de strings (o NlsValidateLocale do KERNELBASE num processo do SYSTEM), tinha
1 a 2% da CPU e ficava à frente da fila da prioridade dele por segundos. A
linha `[perf] servicos:` conta os retornos diretos e as saídas lentas por
motivo, e a `[perf] threads:` as cinco threads com mais tempo de
intervalo. A linha `[perf]` mostra também o tempo gasto escrevendo na
serial e os bytes escritos (`hal/serial.rs`): no WHPX cada byte do log
custa cerca de 5 µs, porque o 16550 do QEMU entrega byte a byte ao
arquivo da serial. O perfil por amostragem (`kd/sampler.rs`, `--perfil`
ou `--perfil=nmi`, a opção de carga PROFILE) amostra o processador de boot
pelo tique do relógio (100 Hz; só o que roda com IF=1, e um serviço, que
roda com IF=0, aparece no `ret` do stub) ou pelas NMIs que o test-boot
injeta pelo QMP a cada 2 ms (também os serviços e os ISRs; só com uma CPU,
depois da linha `[perfil]` do kernel). Cada amostra do anel 0 leva a
cadeia de frame pointers; o tique agrega por janela e escreve, depois de
cada `[perf]`, linhas `[pf]`: o anel 3 por (pid, módulo+deslocamento), o
anel 0 pela pilha e os serviços por (pid, número) com as chamadas, as
falhas e o tempo dos que voltaram sem trocar de thread. `cargo xtask
perfil SERIAL [--de=S] [--ate=S] [--pid=N]` soma as janelas e dá os nomes
(o `kernel.elf` ao lado da serial, os exports ou o PDB do cache dos
módulos desta máquina, os stubs da ntdll e do win32u). O autoteste `ntos/test/multiprocess/service_exit.rs` liga a volta direta e confere
muitas chamadas por intervalo num serviço que só conta, o fim do intervalo
num serviço que sinaliza (a thread de prioridade maior que esperava roda
antes da sinalização seguinte) e, numa espera adiada repetida com um
sinaliza-e-limpa a cada volta, todas as esperas concluídas e nenhum
STATUS_PENDING no anel 3. Um despacho aninhado (um pump dentro do
despacho) devolve `Idle`, e só o BSP despacha usuário (assert). Um processo
entra no despachante por `ps/user/process.rs::start_created` (o CONTEXT do
LdrInitializeThunk e o registro da thread principal) e anda com os outros,
esperado ou não; `wait_started`/`threads::wait_for_process` bloqueia quem
precisa do fim dele despachando todos enquanto espera (`run_created` é os
dois juntos). O `scheduler::tick` também despacha: quando a thread mais
prioritária das filas é de usuário, dá até `USER_SLICES_PER_TICK`
intervalos, se a CPU pode despachar usuário (`threads::can_dispatch`: o
BSP, PASSIVE_LEVEL, nenhuma trava retida, nada de usuário em curso), então
processos em segundo plano andam pelo laço do kmain e pelos pumps das
esperas, e o timer, que encerra o intervalo de quem não cede a CPU, alterna
entre eles. O fim de um processo tem um caminho só,
`ps/create.rs::exit_process` (o PspExitProcess): a falha na criação, o
descarte, o NtTerminateProcess dele mesmo (o intervalo termina de vez e o
despachante pede o fim), uma exceção fatal, uma falha de despacho e o
NtTerminateProcess por handle de outro processo (PROCESS_TERMINATE), que
termina o alvo sem tocar em quem chamou. O ZwTerminateProcess de um driver
é o NtTerminateProcess de KernelMode (`create::terminate_by_handle`): o
handle (de kernel ou da tabela do processo corrente) passa pelo
ObReferenceObjectByHandle com PROCESS_TERMINATE, um processo de usuário
termina pelo mesmo `exit_process` (um fim já pedido dá
STATUS_PROCESS_IS_TERMINATING), o NULL fora de um processo seguro é
STATUS_NOT_SUPPORTED e as threads de sistema não terminam de fora
(STATUS_ACCESS_DENIED). O KPROCESS só fica sinalizado no fim do término,
depois da última thread e do callout de saída de processo, e o
ZwWaitForSingleObject espera nele: o TerminateUmfdHost do win32kfull, que
o winlogon pede ao sair, termina o fontdrvhost da sessão assim e só depois
esquece o hospedeiro (UmfdHostLifeTimeManager::s_UmfdHostProcess); as
threads dele, inicializadas pelo caminho do hospedeiro de fontes, saem pelo
mesmo caminho (UmfdUninitializeThread), sem o vUMPDThreadCleanup de uma
lista que esse caminho nunca inicializou. As threads sem estado do win32k
morrem na hora (`threads::begin_exit`: esperas com THREAD_IS_TERMINATING,
fora da fila de prontas); as com Win32Thread recebem o pedido de término do
19041 e saem sozinhas, no contexto delas (veja as esperas que bloqueiam), e
a última a sair conclui o término ali. O término (`finish_exit`: o
post-mortem de um processo que rodou, o `terminate_process` com o callout de
saída de processo do win32k, as notificações no contexto de uma thread dele
e as rotinas de saída, e a liberação das threads) roda já ou, se uma thread
dele tem serviço suspenso no kernel, o próprio término por rodar ou o
intervalo em curso é dele, fica com o despachante, que o conclui depois. Um
fim que espera mais de 64 voltas do despachante roda mesmo assim, com aviso;
com uma thread ainda por rodar o próprio término, a espera vai até 10 s. O
NtTerminateProcess(NULL) termina as outras threads do processo corrente e
quem chamou segue, como o primeiro passo do RtlExitUserProcess. Processos e
threads críticos (`ps/critical.rs`) seguem o 19041: o
EPROCESS.Flags.BreakOnTermination e o
ETHREAD.CrossThreadFlags.BreakOnTermination vêm das
classes ProcessBreakOnTermination e ThreadBreakOnTermination do
NtSet/NtQueryInformation* (o RtlSetProcessIsCritical e o
RtlSetThreadIsCritical da ntdll; marcam-se o smss.exe inicial e a thread
principal dele, o csrss.exe de cada sessão, o wininit.exe e a thread
principal dele e o services.exe). O começo de todo fim de processo
(`create::begin_termination`, no `exit_process` e, na thread que chamou, no
NtTerminateProcess do próprio processo) liga ProcessDelete e passa pela
verificação do PspTerminateAllThreads; o NtTerminateProcess(NULL) liga
ProcessSelfDelete e passa pela mesma verificação; o término de uma thread
confere a thread crítica de um processo sem ProcessDelete nem
ProcessSelfDelete (o PspTerminateThreadByPointer) e a saída da última
thread de um processo crítico (o PspExitThread). O PspCatchCriticalBreak
leva a mensagem do 19041 (com o post-mortem do processo) à serial e ao
depurador e para a máquina com KeBugCheckEx(CRITICAL_PROCESS_DIED, objeto,
1 numa thread e 0 num processo, 0, 0); o CRITICAL_OBJECT_TERMINATION (0xF4)
não sai desse caminho no 19041. O transporte do depurador não atende o
"Break, or Ignore (bi)?" do DbgPrompt: com o host presente, a parada é a do
bugcheck. O autoteste `ntos/test/critical_process.rs` (fase 6) confere as
classes, as condições e os parâmetros sem parar a máquina. A troca de
thread corrente move a CPU em KPROCESS.ActiveProcessors do processo
registrado para o da nova thread (veja a troca de CR3). O autoteste
`ntos/test/multiprocess/all_processes.rs` (fase 7) põe dois processos no
despachante antes de qualquer espera: cada um abre uma seção nomeada, espera
a chegada do outro e, N vezes, incrementa o contador dela, anota o valor e
cede a CPU; os diários mostram os dois avançando antes de qualquer um sair,
e eles saem com códigos distintos. Depois, movidos só pelo tick, um processo
que gira no anel 3 sem syscall é terminado por handle por outro, que abre o
alvo pelo CLIENT_ID e segue vivo: logo depois do término a vítima não tem
estado, threads, vista nem pilha de kernel, e a raiz dela fica só com a
KUSER, enquanto o matador termina as voltas e sai com o próprio código. Por
fim, com uma segunda thread viva, a principal chama
NtTerminateProcess(NULL), recebe sucesso e sai depois com o próprio código;
a segunda morreu com o status pedido.

**Diagnóstico de falhas de usuário.** `ps/user/crash_report.rs` só escreve
na serial; não muda despacho, serviços nem término. Uma falha de processo
de usuário imprime um bloco `[crash]` a partir de um destes pontos: a
segunda chance do NtRaiseException, a exceção que não chega ao
KiUserExceptionDispatcher, o NtRaiseHardError de uma exceção (o
STATUS_UNHANDLED_EXCEPTION do UnhandledExceptionFilter, com código e
endereço nos parâmetros), o NtSetSystemInformation(177,
SystemWin32WerStartCallout) do relatório de falha da kernel32 e o fim do
processo com status de exceção (ali o bloco substitui o post-mortem comum
do `finish_exit`). O bloco traz processo, pid:tid, código e endereço da
exceção, módulo + deslocamento (lista InLoadOrder do PEB_LDR_DATA ou, fora
dela, uma região nomeada do VAD do processo ou do System), o export mais
próximo e até dez quadros da pilha de usuário desenrolados pela .pdata de
cada módulo (`rtl/frame_walk.rs`). Cada exceção entregue fica anotada na thread (código,
endereço, registradores e o frame do CONTEXT), então o bloco de um ponto
posterior desenrola a pilha da própria falha; sem anotação, a pilha sai da
chamada de sistema, sem os quadros do despacho em modo usuário. Cada
processo imprime um bloco por código, e toda leitura de memória de usuário
confere antes a página presente e a posse (`memory::check_user_access`).

**Diagnóstico dos serviços gráficos do win32k.** Os serviços da tabela do
win32k vão do stub do win32u.dll direto à rotina do driver
(`hal/amd64/usermode.rs`), fora do registro de serviços nativos, então a
linha FALHOU de `ps/user/index.rs` não os vê. `ps/user/win32k_status.rs`
acompanha os que devolvem NTSTATUS e chegam ao dxgkrnl ou à composição
(NtGdiDdDDI*, NtDxgk*, NtDComposition*, NtTokenManager*, NtFlipObject*,
os *CompositionSurface* e os NtUser*DisplayConfig* da configuração de
vídeo): uma falha imprime `[win32k] pid:tid Nome FALHOU
com status (chamador módulo+deslocamento)`. Os nomes saem dos stubs do
win32u.dll do primeiro processo que falha; cada par (serviço, status)
imprime as quatro primeiras vezes e depois uma a cada 256. Só escreve na
serial; o resultado volta ao modo usuário como veio.

**Retomada do pop de SList de usuário.** `ke/user_slist.rs` guarda os
exports ExpInterlockedPopEntrySListResume, ...Fault e ...End da ntdll
quando ela é mapeada (`ps/user/loader.rs`). Como no KiPreprocessFault do
19041, a falta de página de usuário com o RIP no ...Fault não vira exceção
(`ps/user/exceptions.rs::hardware`): o RIP volta ao ...Resume, com o
endereço e a contagem de faltas seguidas na KTHREAD (SListFaultAddress e
SListFaultCount; passada de 0x400, a falta é entregue). Como no
KiCheckForSListAddress, o fim do intervalo de usuário pelo relógio (a troca
do KiDispatchInterrupt; também dentro de um callback) leva um RIP em
(...Resume, ...End] ao ...Resume. Teste: `ntos/test/user_slist.rs`.

**Callbacks de modo usuário.** Um serviço do kernel (o win32k, dentro de
uma syscall da thread) chama uma rotina de usuário pelo KeUserModeCallback
(`ke/user_callback.rs`), como o KiCallUserMode do NT: confere o contexto
(IRQL, anexação, APCs; os bugchecks do NT), conta o aninhamento em
KTHREAD.CallbackNestingLevel, cria uma pilha de kernel nova com o
KERNEL_STACK_CONTROL preenchido (o segmento anterior e, em
Previous.KernelStack, o quadro do callout), monta o UCALLOUT_FRAME e a cópia
da entrada abaixo do RSP da syscall (o CONTEXT do intervalo faz o papel do
KTRAP_FRAME; `opennt_user_syscall` o preenche na entrada do serviço, antes da
busca na tabela, como o KiSystemServiceStart grava KTHREAD.TrapFrame, porque
a conversão em thread GUI já chama o win32k, que faz um callback de dentro
dela) e troca a KTHREAD para a pilha nova. O intervalo do callback é
aninhado no serviço: `usermode::exec_user_callback` guarda o estado por CPU
do serviço de fora (o quadro do despachante, o CONTEXT e o quadro da
syscall, RspBase/RSP0, GS e IF) e entra num CONTEXT próprio em
ntdll!KiUserCallbackDispatcher (o KeUserCallbackDispatcher, publicado quando a
DLL de sistema é mapeada), com os registradores do KiCallUserMode; as
syscalls do callback caem na pilha nova, abaixo dos quadros do serviço de
fora. `threads::run_callback` despacha esses intervalos até o
NtCallbackReturn, que acha o quadro do callout pelo KERNEL_STACK_CONTROL da
InitialStack corrente e grava a saída e o status: syscalls seguem, APCs e
exceções são entregues no CONTEXT do callback e uma thread terminada encerra
o laço. Uma thread com o término pedido (as com Win32Thread) recebe a APC de
término na volta ao anel 3 do callback, como no KiCallUserMode: o
PspExitThread roda no laço, na pilha de fora (que volta à KTHREAD), e ela não
volta ao serviço que chamou o KeUserModeCallback (o win32k, no
ClientDeliverUserApc depois do STATUS_USER_APC); cada nível de fora acaba no
fim do intervalo aninhado dele. A pilha, o quadro do callout e o CONTEXT de
cada KeUserModeCallback abandonado ficam num registro por thread e voltam pelo
ceifador (`user_callback::release_abandoned`). Dentro do callback a thread
continua escalonável, como no NT: os
intervalos aninhados terminam no laço do callback, não no despachante, então
é o laço que repassa a troca. Um serviço aninhado que bloqueia no kernel sai
do intervalo aninhado com EXIT_BLOCKED e deixa o quadro de troca em
KTHREAD.KernelStack; uma syscall aninhada que volta PENDING deixa a espera
adiada instalada; o timer encerra o intervalo no fim do quantum. Nos três
casos o laço põe na KTHREAD a pilha do serviço de fora (`CalloutStacks`),
bloqueia esse serviço pela espera já instalada
(`context_switch::block_installed_wait`) e o despachante roda as outras
threads; retomado, o laço reinstala a pilha do callback e volta ao serviço
aninhado (`usermode::resume_user_callback`, um intervalo aninhado que entra no
quadro de troca salvo) ou põe o status da espera adiada no RAX do callback.
Com callbacks aninhados cada nível repassa ao de fora até o despachante, e a
retomada desce nível a nível. Na volta, a KTHREAD retoma a pilha anterior e a
do callback volta ao Mm. O autoteste `ntos/test/multiprocess/user_callback.rs`
roda callbacks simples, aninhados, a volta pelo NtCallbackReturn do
KiUserCallbackDispatcher real, a entrada que não cabe na pilha, o
NtCallbackReturn fora de um callback e um callback que espera no kernel e
numa espera adiada, conferindo que o despachante sonda as duas com a thread
fora da CPU. O lote GDI da TEB (TEB.GdiBatchCount) vai ao win32k pelo
callout 7 (`ps/win32.rs::flush_gdi_batch`) na volta de cada callback e,
como no KiSystemServiceGdiTebAccess, antes de todo serviço da tabela 1:
`opennt_user_syscall` o esvazia depois da busca na tabela (e da conversão em
thread GUI) e antes de copiar os argumentos.

O espaço de usuário segue o Windows 10 19041 x64, sem nenhuma janela fixa
além da KUSER_SHARED_DATA:

| Constante (`memory_map.rs`) | Valor | No NT |
| --- | --- | --- |
| `LOWEST_USER_ADDRESS` | 0x10000 | MM_LOWEST_USER_ADDRESS: os primeiros 64 KB nunca são mapeáveis |
| `HIGHEST_VAD_ADDRESS` | 0x7FFF_FFFD_FFFF | MM_HIGHEST_VAD_ADDRESS: topo das alocações e do MEM_TOP_DOWN |
| `HIGHEST_USER_ADDRESS` | 0x7FFF_FFFE_FFFF | MmHighestUserAddress (export) |
| `USER_PROBE_ADDRESS` = `USER_ADDRESS_LIMIT` | 0x7FFF_FFFF_0000 | MmUserProbeAddress (export) |
| `ALLOCATION_GRANULARITY` | 0x10000 | granularidade de alocação |

- **Alocação** (`ps/user/memory.rs`, escolha em `mm/section/address.rs`):
  sem base, a primeira faixa livre alinhada a 64 KB de baixo para cima a
  partir de 64 KB, como o MiFindEmptyAddressRange (MEM_TOP_DOWN: a primeira
  de cima para baixo a partir de MM_HIGHEST_VAD_ADDRESS), sem cursor: uma
  faixa liberada volta a ser a primeira candidata. Com base, a reserva desce a
  64 KB (o commit sobre uma reserva fica em páginas); uma base abaixo de
  64 KB ou acima do último VAD falha com STATUS_CONFLICTING_ADDRESSES (como o
  MiIsVaRangeAvailable), e uma base além de MmHighestUserAddress com
  STATUS_INVALID_PARAMETER. MEM_COMMIT sem MEM_RESERVE só confirma o que já
  está reservado: com base fora de uma reserva (ou passando do fim dela),
  STATUS_CONFLICTING_ADDRESSES, como o MiAllocateVirtualMemory do 19041;
  sem base, reserva uma faixa nova. Vistas de seção usam a mesma escolha.
- **Proteções, guarda e write watch** (`ps/user/memory.rs`,
  `mm/guard_page.rs`, `mm/write_watch.rs`, `mm/control_flow_guard.rs`):
  - A proteção de uma alocação privada passa pelo MiMakeProtectionMask
    (`mm/protection.rs`): PAGE_GUARD, PAGE_NOCACHE e PAGE_WRITECOMBINE valem
    nas combinações do 19041. Os dois de cache ficam só na proteção
    registrada; a página segue em cache. Em vistas de seção e imagens os
    modificadores ainda dão STATUS_NOT_SUPPORTED.
  - Nenhum processo tem CFG (um estado válido do 19041):
    PAGE_TARGETS_INVALID na alocação (só com proteção executável, senão
    STATUS_INVALID_PAGE_PROTECTION) e PAGE_TARGETS_NO_UPDATE na proteção (só
    com uma proteção executável simples, senão STATUS_INVALID_PARAMETER_4)
    são conferidos e retirados. A classe 2 do NtSetInformationVirtualMemory
    (SetProcessValidCallTargets) confere a lista e responde
    STATUS_INVALID_PAGE_PROTECTION com NumberOfEntriesProcessed 0.
  - MEM_COMMIT sobre páginas já comitadas com outra proteção troca a
    proteção da faixa depois do commit, como o MiAllocateVirtualMemory chama
    o MmProtectVirtualMemory: é o RW→RX do JIT do d3d10warp. O
    NtFlushInstructionCache devolve sucesso sem conferir nada, como o do
    19041 (`xor eax, eax; ret`).
  - Uma página de guarda fica comitada com a PTE ausente. O primeiro acesso
    que a proteção base admite tira a guarda (o MiAccessCheck) e dá
    STATUS_GUARD_PAGE_VIOLATION; na pilha da thread (DeallocationStack e
    StackBase da TEB) a pilha cresce como no MiCheckForUserStackOverflow:
    guarda nova abaixo da página, StackLimit na página e o acesso repete, ou
    STATUS_STACK_OVERFLOW sem espaço. A falta de usuário e as sondas do
    kernel (`probe_user_access`) passam por aí; uma falta de código nativo
    do kernel numa guarda de usuário ainda é STATUS_ACCESS_VIOLATION.
  - MEM_WRITE_WATCH (só com MEM_RESERVE) marca a alocação. NtGetWriteWatch e
    NtResetWriteWatch leem e limpam o bit Dirty das PTEs e o bitmap da
    região, que recebe o bit Dirty quando a PTE é reescrita ou sai do
    working set. Uma escrita do kernel pelo mapa direto (a cópia do
    NtWriteVirtualMemory para outro processo) não aparece.
  - Teste: `ntos/test/user_jit_memory.rs`.
- **Tabelas de funções dinâmicas** (`rtl/dynamic_function_table.rs`): o
  RtlAddGrowableFunctionTable da ntdll, com que o JIT do d3d10warp registra
  o unwind de cada bloco, chama o NtSetInformationProcess(NtCurrentProcess(),
  ProcessDynamicFunctionTableInformation = 53) com o {Table, Remove} de 16
  bytes (`ps/set_process_information.rs::set_dynamic_function_table`: outro
  handle é STATUS_INVALID_PARAMETER, outro tamanho
  STATUS_INFO_LENGTH_MISMATCH). O RtlInsertDynamicFunctionTable e o
  RtlRemoveDynamicFunctionTable mantêm o INVERTED_FUNCTION_TABLE do
  EPROCESS.InvertedFunctionTable (pool 'RtDF' com quota, crescendo de 10 em
  10 entradas, sob o InvertedFunctionTableLock numa região guardada): faixas
  ordenadas pela base a partir da entrada 1, sobreposição dá
  STATUS_CONFLICTING_ADDRESSES, faixa invertida ou acima de 4 GB
  STATUS_INTEGER_OVERFLOW, retirada sem a mesma base e o mesmo tamanho
  STATUS_BAD_FUNCTION_TABLE. A busca do RtlpLookupUserFunctionTable
  (`lookup`) é a parte do kernel no desenrolamento de pilhas de usuário; o
  fim do processo libera o vetor. Teste:
  `ntos/test/dynamic_function_tables.rs`.
- **O que o kernel monta para o processo** também sai do alocador: a pilha da
  primeira thread é uma alocação de baixo para cima (fica abaixo de 4 GB
  num processo novo); PEB, TEB, parâmetros, entradas do Ldr e as regiões
  compartilhadas de NLS são páginas comitadas de cima para baixo, como o
  MiCreatePebOrTeb. A escolha é por raiz (`memory::occupied(space)`): o VAD
  dos processos que usam a raiz do espaço (só o do processo, quando a raiz é
  própria), as vistas mapeadas nela, as PTEs dela
  (`section_address::FindOptions::root`) e as faixas de sistema que todo
  processo vê na mesma VA (a KUSER_SHARED_DATA, a ntdll, o apiset e o NLS).
  Dois processos com raiz própria usam a mesma VA sem conflito.
- **VAD por processo** (`memory::Vad`, no `ProcessState` de cada EPROCESS):
  as alocações privadas, as vistas de seção e as imagens são do processo que
  as criou. Cada lista (`memory::RegionList`) guarda a ordem de inserção e
  um índice pela base, mantido em cada inserção e remoção: a busca por
  endereço (a de cada sonda de memória de usuário no modo estrito de posse)
  desce o índice, como o MiLocateAddress desce a árvore do VadRoot; se duas
  regiões de uma lista se sobrepõem, a busca volta à varredura em ordem, com
  a mesma resposta. Antes a varredura linear era um terço do tempo de kernel
  do explorer, que enumera diretórios com milhares de regiões no VAD. Os serviços agem sobre um `memory::Space`, o do processo do
  handle (o pseudo-handle é o corrente, o anexado quando há attach): os Nt*
  de usuário, os Zw* e o NtMapViewOfSection (seção 4, memória entre
  processos). NtQueryVirtualMemory, NtFreeVirtualMemory e
  NtProtectVirtualMemory só enxergam o VAD do processo do handle; o System
  guarda o que o kernel aloca no próprio contexto e as
  cópias de sistema da ntdll, do apiset e do NLS. O término do processo
  devolve o VAD inteiro (`memory::release_vad`, o MmCleanProcessAddressSpace),
  e a montagem de um processo novo roda anexada a ele, como o MmCreatePeb.
  Mapear, desfazer e reproteger editam a raiz do espaço explicitamente
  (`Space::root`, `paging::*_in`), carregada ou não: um Zw* sobre outro
  processo e o término (que roda no contexto de quem termina) mexem nas
  tabelas do dono, nunca nas do CR3. As vistas de seção guardam a raiz em
  que estão (`View::root`, `ImageView::root`); confirmar páginas publica o
  alias em cada vista na raiz dela, e a falta copy-on-write só procura as
  vistas da raiz carregada.
- **Imagens de usuário** carregam na ImageBase do cabeçalho quando a faixa
  está livre no espaço do processo (um .exe em 0x1_4000_0000) e, se não
  estiver, na primeira faixa livre, relocadas (STATUS_IMAGE_NOT_AT_BASE nas
  vistas de imagem). O `pe_loader` mapeia sempre no processo corrente, na
  raiz carregada, e desfaz na mesma raiz. A imagem principal é do processo
  (`ProcessState`) e é desfeita no término dele.
- **Seções de imagem** (`mm/section/image_segment.rs`, o
  MiCreateImageFileMap): a primeira vista de um arquivo SEC_IMAGE monta as
  páginas protótipo da control area, frames do PFN com os cabeçalhos e as
  seções do PE no layout virtual (o `pe_loader` com `prototype`: sem VA,
  sem relocação, sem imports, sem cookie e sem a tabela de exports; a carga
  entrega a lista de frames à control area, que os devolve ao PFN). Todas
  as seções do mesmo arquivo usam a mesma control area (o papel do
  ImageSectionObject): a chave é o arquivo do volume pelo registro do MFT e
  a sequência (`SectionFile::file_id`), igual em toda abertura, também nas
  do modo usuário, em que cada abertura tem o seu FILE_OBJECT (o LdrLoadDll
  de cada processo); sem ele, a identidade do arquivo. Uma seção
  SEC_IMAGE_NO_EXECUTE (a carga só de recursos) tem a sua control area do
  arquivo, com as páginas todas somente leitura. A seção e cada vista a
  retêm.
  Sem seção nem vista, a control area de um arquivo segue na lista das sem
  uso (a MmUnusedSegmentList do 19041, em que o MiCheckControlArea a põe
  com as páginas protótipo em standby): a seção seguinte do mesmo arquivo
  usa as mesmas páginas sem ler o arquivo, se ele não mudou (o tamanho e as
  horas de escrita e de mudança do $STANDARD_INFORMATION de quando ela foi
  montada; um arquivo mudado ganha outra). As sem uso passam de um oitavo
  da memória física (até 128 MB) ou voltam ao PFN pela recuperação de
  memória (`page_residency`, o MiDeleteUnusedSegments), a mais antiga
  primeiro. Antes, metade dos bytes de imagem lidos no boot até a tela de
  logon era de recargas (o d3d10warp.dll seis vezes, a kernelbase.dll
  cinco). Teste: `retained_image_segments` na fase 7. O
  NtAreMappedFilesTheSame (`are_mapped_files_the_same`, 19041 0x6a0330)
  acha a vista de cada endereço no registro do processo, de dados ou de
  imagem: a vista de imagem dá STATUS_SUCCESS contra outra vista do mesmo
  arquivo do volume (o registro do arquivo, `SectionFile::file_id`, igual
  em toda abertura), e o LdrpFindLoadedDllByMappingLockHeld da ntdll usa o
  módulo que já existe quando a mesma DLL chega por outro caminho (o
  explorer, em `\Windows`, carrega os imports de System32 por
  `C:\Windows\X.dll`, e o gancho de API do win32k pede o UxTheme.dll por
  `C:\Windows\system32`). Teste: `mapped_images` em
  `user_desktop_services`. A vista (`image_view.rs`, o
  MiMapViewOfImageSection) mapeia na raiz do processo as páginas de código
  e somente leitura sobre os frames protótipo, divididos entre os processos
  e sem escrita, e as páginas graváveis sobre cópias privadas feitas no
  mapeamento (o copy-on-write do protótipo já resolvido). Uma página
  dividida que o NtProtectVirtualMemory torna gravável ganha antes a cópia
  privada do processo (`UserRegion::write_copy`; no NT, PAGE_READWRITE numa
  vista de imagem é PAGE_WRITECOPY): a relocação e a IAT que a ntdll de um
  processo grava não aparecem em outro. O heap do kernel guarda só os
  vetores de frames e de proteções da vista (12 bytes por página). Antes,
  cada vista recarregava a imagem inteira em frames novos e guardava duas
  cópias da tabela de exports no heap (a da carga e a do processo); com
  uns dez processos e as DLLs deles, o heap de 64 MB acabava no boot do
  smss real ao mapear o scesrv.dll no services.exe.
  O cabeçalho passa antes pelas regras do MiVerifyImageHeader e do
  MiCreateImageFileMap (`mm/section/image_header.rs`), as mesmas para o
  NtCreateSection de usuário, o KnownDlls e a seção da CI: os alinhamentos
  (um FileAlignment fora de múltiplo de 512 só igual ao SectionAlignment),
  o SizeOfImage arredondado à página (o tamanho da seção) e a tabela de
  seções dentro dele. Um SectionAlignment menor que a página (o 0x80 do
  E1G6032E.sys) é a imagem plana: cada seção com PointerToRawData igual ao
  VirtualAddress, o arquivo inteiro a partir do offset zero numa faixa só,
  zero depois do fim do arquivo, toda MM_EXECUTE_WRITECOPY (PAGE_EXECUTE_WRITECOPY
  no backing de sistema, cópias privadas PAGE_EXECUTE_READWRITE nas vistas de
  processo) e ImageMappedFlat na SECTION_IMAGE_INFORMATION.
- **Seções sobre arquivos de um file system real** (`mm/section/fsd_file.rs`,
  `mm/page_io.rs`, `cc/cache_section.rs`): um FILE_OBJECT servido pela
  pilha de um file system (o ntfs.sys do volume E: com `--storage=nvme`) dá
  seção de dados e de imagem. A control area é a do stream, achada pelos
  SECTION_OBJECT_POINTERS do FCB (a identidade `sop:<endereço>`): todo
  handle do mesmo arquivo e o cache usam os mesmos frames. A criação roda
  com o arquivo adquirido pelo FsRtlAcquireToCreateMappedSection
  (SyncTypeCreateSection pelos callbacks do file system; o do ntfs.sys
  devolve STATUS_FILE_LOCKED_WITH_ONLY_READERS ou _WITH_WRITERS, que são
  sucesso), o tamanho vem do FsRtlGetFileSize, e um tamanho máximo maior
  estende o arquivo pelo FsRtlSetFileSize (o IRP de paginação 0x42 do
  0x669a10). Uma seção de dados liga FSRTL_FLAG_USER_MAPPED_FILE no
  cabeçalho do FCB, como o CcZeroEndOfLastPage. A seção de dados é
  paginada sob demanda, como a do MiCreateDataFileMap: a criação não lê o
  arquivo, e a falta de uma página ausente numa vista (de usuário, de
  sistema ou uma sonda do kernel; o provedor `section-file` de
  `page_residency`, o MiResolveMappedFileFault) traz a página e as
  seguintes que faltam, até 16, com a proteção da vista conferida antes. As
  páginas vêm por IoPageRead, até 16 por IRP, num MDL de frames que não
  precisam ser contíguos (com mais de um frame, PTEs de sistema durante a
  E/S dão o MappedSystemVa). O frame só entra na control area depois da
  leitura; uma página que outro caminho publicou nesse meio tempo fica com
  o frame dele. Uma vista dessas conta toda a faixa dentro da seção como
  confirmada (NtQueryVirtualMemory), e o NtProtectVirtualMemory guarda a
  proteção das páginas que ainda não vieram. O estado das páginas é o do
  NT: o bit Dirty das PTEs das vistas que não são do cache passa ao bit
  Modified da página na control area (o MiCaptureDirtyBitToPfn), com o
  shootdown dos TLBs antes de a página contar como capturada, no flush, na
  retirada de cada PTE (uma troca atômica, o MiDeletePte) e antes de uma
  PTE ser regravada com outra proteção. O flush (o MmFlushSection, também o
  do CcFlushCache sem SharedCacheMap) grava cada sequência de páginas
  modificadas vizinhas numa escrita de paginação (IoSynchronousPageWrite,
  até 16 páginas por IRP, como o cluster do MiFlushSectionInternal) pelo
  FILE_OBJECT da CONTROL_AREA. O writer de páginas mapeadas
  (`mm/mapped_writer.rs`, o MiMappedPageWriter) é uma thread de sistema que
  a cada 5 s, ou acordada, colhe o bit Dirty das vistas e grava as páginas
  modificadas com o arquivo adquirido pelo FsRtlAcquireFileForModWriteEx
  (`fsrtl/fs_filter.rs`: os filtros, o Fast I/O AcquireForModWrite do file
  system, sem espera, e o recurso do FCB sem ele; STATUS_CANT_WAIT deixa o
  arquivo para a passada seguinte) e o FSRTL_MOD_WRITE_TOP_LEVEL_IRP como
  IRP de nível de topo; uma vista que fica aberta não guarda as alterações
  só na memória. As vistas do Cache Manager ficam fora da captura: o que o
  cache altera sai pelo flush do Cc, com o write-ahead do log, e as control
  areas com NoModifiedWriting ficam fora do writer. A última referência da
  control area grava o que ainda está modificado (o MiCleanSection). A
  CONTROL_AREA nativa (`mm/section/control_area.rs`) vai ao DataSectionObject
  do FCB com a primeira seção do stream (a do Cache Manager ou uma de
  usuário) e sai com a última: a CONTROL_AREA, o MSUBSECTION que cobre o
  tamanho mapeado (que o MmExtendSection estende), a raiz da árvore de
  subseções e o SEGMENT, com os contadores da control area do OpenNT
  (seções, vistas mapeadas e do cache, referências de usuário e as
  graváveis, páginas residentes), u.Flags.File e o FILE_OBJECT referenciado
  em FilePointer. O ntfs.sys e as rotinas do Mm que recebem os
  SECTION_OBJECT_POINTERS (MmCanFileBeTruncated, MmForceSectionClosed,
  MmDoesFileHaveUserWritableReferences, MmChangeSectionBackingFile,
  MmPrefetchPages) veem a seção; o NtfsSetEndOfFileInfo de um arquivo
  mapeado com escrita recusa o truncamento com STATUS_USER_MAPPED_FILE. A
  troca do slot e a leitura dele pelas rotinas do Mm ficam sob um lock de
  associação, e a CONTROL_AREA retirada nunca é lida depois de liberada.
  Antes de ler uma imagem roda o MiFlushDataSection: CcFlushCache e o flush
  das vistas de dados. O cache usa a mesma control area: o
  CcInitializeCacheMap cria a seção do stream (SharedCacheMap->Section), e
  cada vista de 256 KB do Cc é uma vista de sistema dela; ReadFile,
  WriteFile e as vistas de usuário veem o mesmo frame. O purge do Cc tira
  da control area as páginas que nenhuma vista de usuário mapeia (o
  MmPurgeSection), o CcFlushCache de um arquivo mapeado por usuário grava
  antes as vistas (o primeiro passo do 19041), e o MmSetAddressRangeModified
  de uma página suja de uma vista do cache a marca suja no Cc. O
  CcAsyncCopyRead (a leitura em cache de um handle assíncrono, o
  NtfsAsyncCachedReadRequest do ntfs.sys) chama a rotina de conclusão do
  CC_ASYNC_READ_CONTEXT, que conclui o IRP. Diferenças declaradas: a
  leitura do CcAsyncCopyRead é síncrona, no contexto de quem pede (o NT
  devolve com a E/S em curso); a escrita do writer de páginas mapeadas é
  síncrona, um cluster por vez; as páginas de uma control area de arquivo
  de file system ficam residentes até a control area sumir ou o purge do
  Cc (sem lista de espera nem corte das vistas); nenhuma CONTROL_AREA vai
  ao ImageSectionObject. A criação de processo aceita um executável fora do volume
  do kernel (`ps/create.rs`, `DriverImage`): o I/O Manager abre o arquivo
  como o IoCreateFileEx do NtCreateUserProcess e a imagem é lida pela E/S
  de paginação. As aberturas de usuário de uma letra que leva a um volume
  que não é do kernel vão ao IopParseDevice do volume (`ps/user/files.rs`),
  e o NtQueryAttributesFile desses nomes abre, consulta e fecha pelo file
  system. Testes: nvme (NVME_SECTION_OK e FSD_MAPPED_OK, de
  `ntos/test/fsd_mapped.rs`) e e-process (E_PROCESS_OK).
- **`\Device\PhysicalMemory`** (`mm/section/physical_memory.rs`, o
  MiSectionInitialization): criada no boot com o namespace, permanente e
  com OBJ_KERNEL_EXCLUSIVE. O corpo SECTION aponta para uma CONTROL_AREA
  com u.Flags.PhysicalMemory e um SEGMENT ligado a ela, com SizeOfSection
  0xFFFFFFFFFFFF. O ZwOpenSection de modo kernel abre (o dxgmms2.sys a
  abre ao iniciar um adaptador de renderização); UserMode ou
  OBJ_FORCE_ACCESS_CHECK recebem STATUS_ACCESS_DENIED, o KernelOnlyAccess
  que `ob/objects/section.rs` aplica às seções marcadas. Vistas dela (o
  MiMapViewOfPhysicalSection) ainda não existem: o NtMapViewOfSection
  recusa com uma linha `[section]` na serial.
- **NtExtendSection** (`mm/section/extend.rs`, o MmExtendSection do
  19041): uma seção de dados de arquivo cresce; a de imagem, a sem arquivo
  e a de `\Device\PhysicalMemory` dão STATUS_SECTION_NOT_EXTENDED, e um
  tamanho que não passa do SizeOfSection volta como ele. Acima do arquivo,
  a seção precisa ser gravável e o arquivo cresce pelo mesmo resize do
  MmCreateSection (`SectionFile::set_size`, `mm/section/file.rs`); o
  SizeOfSection e o tamanho em páginas da seção (`Section::extend`, agora
  atômicos) crescem, com as páginas novas confirmadas na control area como
  na criação, e as vistas novas cobrem a faixa nova. Num arquivo de file
  system o tamanho do arquivo vem do FsRtlGetFileSize, o arquivo cresce pelo
  FsRtlSetFileSize (o IRP_MJ_SET_INFORMATION ao file system), as páginas
  novas vêm pela falta e a CONTROL_AREA publicada passa a descrever o
  tamanho novo. O NewSectionSize volta
  com o tamanho que ficou, qualquer que seja o status. Como no 19041, a
  seção de arquivo guarda o SizeOfSection pedido (ou o tamanho do arquivo)
  sem arredondar à página.
- **NtCreateSectionEx e NtMapViewOfSectionEx** (`mm/section/create.rs`,
  `mm/section/map_view.rs`): os parâmetros estendidos passam pelas capturas
  do 19041 (`mm/extended_parameters.rs`: o vetor sondado para escrita, um
  tipo de cada, o cabeçalho sem bits reservados, o nó como nó + 1). A seção
  aceita UserPhysicalFlags e NumaNode, recusa os bits de nó no
  AllocationAttributes, e a seção de páginas físicas de usuário (AWE) passa
  pelas regras do MiCreatePagingFileMap até o SeLockMemoryPrivilege
  (`mm/physical_pages.rs`). Os serviços AWE (NtAllocateUserPhysicalPages(Ex),
  NtFreeUserPhysicalPages, NtMapUserPhysicalPages(Scatter)) fazem as
  checagens do 19041 até a AweInfo, que o OpenNT ainda não tem: a alocação
  termina em STATUS_PRIVILEGE_NOT_HELD (com uma linha `[awe-boundary]` quando
  o processo tem o SeLockMemoryPrivilege), a liberação e os mapeamentos em
  STATUS_INVALID_PARAMETER_1 (sem AweInfo e sem VAD AWE). A vista é ViewShare, sem ZeroBits nem
  CommitSize, com AddressRequirements (o MiMapExParametersInitialize: sem
  Alignment, LowestStartingAddress na granularidade, HighestEndingAddress
  no fim de uma página e até 0x7FFFFFFEFFFF, nada com uma base pedida),
  NumaNode e o AttributeFlags SOFT_FAULT_PAGES; a base e o deslocamento
  fora da granularidade dão STATUS_MAPPED_ALIGNMENT, e o
  MEM_REPLACE_PLACEHOLDER não acha placeholder (STATUS_CONFLICTING_ADDRESSES).
- **Seções do VidMm e do DirectComposition** (`mm/section/create.rs`,
  `insert.rs`, `ps/user/sections.rs`): uma seção de pagefile com SEC_COMMIT
  tem os frames confirmados na criação, e toda vista (a de sistema, a de
  sessão, as dos processos e as PTEs de sistema de um MDL travado) é alias
  dos mesmos frames. As páginas confirmadas de uma seção de pagefile (na
  criação com SEC_COMMIT ou pelo MEM_COMMIT numa vista SEC_RESERVE) cobram o
  commit do sistema (`mm/commit.rs`, limite = RAM mais arquivos de
  paginação), como o MiChargeCommitment do 19041, e a recusa é
  STATUS_COMMITMENT_LIMIT; a cobrança volta com a control area. Diferença
  declarada: o NT dá os frames no primeiro toque e o OpenNT os dá na
  confirmação, zerados, porque nenhuma daquelas vistas tem ainda a falta
  que materializaria a página em todas; sem frames livres para páginas já
  cobradas, a recusa é STATUS_NO_MEMORY com uma linha `[section]` na
  serial. O MmCreateSection devolve o SECTION ainda como objeto
  novo; o ObInsertObject dele (`insert.rs`, chamado pelo
  `ob/object_create.rs` para um corpo de seção) abre o handle de criação,
  publica um nome capturado e solta a referência de criação, e um segundo
  ObInsertObject dá STATUS_INVALID_PARAMETER. O dxgmms2 insere assim o
  backing store de cada alocação e depois o abre por ponteiro em UserMode
  com acesso 0 (seção sem descritor). SEC_NO_CHANGE na criação marca a seção
  e toda vista dela recusa trocar a proteção, como no MiMapViewOfDataSection.
  Desmapear segue o MiUnmapViewOfSection: num VAD NoChange o
  MiCheckSecuredVad da remoção (0x55) recusa, com
  STATUS_INVALID_PAGE_PROTECTION e em qualquer modo, só a vista com uma faixa
  protegida por MmSecureVirtualMemory (`mm/secure_memory.rs`); a vista
  SEC_NO_CHANGE sem faixa protegida desmapeia normalmente, inclusive pelo
  NtUnmapViewOfSection de usuário. O NtUnmapViewOfSectionEx aceita
  MEM_UNMAP_WITH_TRANSIENT_BOOST (no NT só muda a prioridade das páginas
  soltas na lista de espera, que o OpenNT não tem) e
  MEM_PRESERVE_PLACEHOLDER (base de página, senão
  STATUS_INVALID_PARAMETER_2; como nenhuma vista do OpenNT vem de um
  placeholder, STATUS_CONFLICTING_ADDRESSES depois da checagem de
  segurança); outras flags dão STATUS_INVALID_PARAMETER_3. Testes:
  `ntos/test/shared_section_views.rs` e `ntos/test/secure_virtual_memory.rs`.
- **Faixas protegidas** (`mm/secure_memory.rs`): o MmSecureVirtualMemory(Ex)
  põe uma entrada de segurança no VAD que contém a faixa (a região
  privada, a vista ou a imagem), com as flags do MiAddSecureEntry do 19041
  (leitura, escrita, proteção exata com Flags 2, exclusiva com Flags 1, só
  modo usuário com Flags 4), e o VAD fica NoChange enquanto tiver entradas
  (uma vista SEC_NO_CHANGE já nasce NoChange e recusa a entrada exclusiva).
  O MiCheckSecuredVad roda sobre as entradas do VAD no NtFreeVirtualMemory
  (o MEM_RELEASE confere o VAD inteiro; o MEM_DECOMMIT, da base pedida sem
  arredondar pelo número de páginas), no NtProtectVirtualMemory e no
  MEM_COMMIT sobre o VAD (com a máscara da proteção nova) e no
  desmapeamento; a recusa é STATUS_INVALID_PAGE_PROTECTION. A entrada guarda
  a identidade da região, então uma região que sai do VAD por outro caminho
  leva as entradas dela, e o fim do processo leva todas. Teste:
  `ntos/test/secure_virtual_memory.rs`.
- **Cópias de sistema** (`ps/user/loader.rs`): a ntdll, o apiset e as
  tabelas NLS são mapeados uma vez, na raiz do System (o mapeamento roda
  anexado ao System, venha o pedido de onde vier), e fotografados logo
  depois em frames próprios (`memory::snapshot_system_range`). Cada processo
  com raiz própria recebe na montagem cópias privadas dessas páginas nas
  mesmas VAs e permissões (`loader::map_system_images`, o PspMapSystemDll),
  devolvidas no término. Nenhum frame de usuário com escrita é dividido
  entre processos, e a ntdll de cada processo começa com os dados intactos;
  os exports e o mapa SSN → nome continuam globais (a base é a mesma em
  todos).

O stage2 monta o mapa direto dos 4 GB de baixo (páginas de 2 MB de
supervisor, RW e NX; tabelas em 0x76000-0x7AFFF) antes de entrar no kernel,
e o kernel o estende ao topo da RAM no boot (`mm/direct_map`). A regra:

- **Endereço físico nunca é ponteiro.** Quem tem um PA usa `hal::physical`,
  que traduz pelo mapa direto e para o sistema se receber algo fora da faixa
  física (uma VA, por exemplo). Isso vale para PTEs e tabelas (`paging.rs`),
  descritores de PFN, frames do PFN, MMIO (LAPIC, texto VGA), tabelas ACPI,
  o handoff do stage2 (E820, flags, firmware), as células fixas de baixo
  nível (0x81000 e a IDT em 0x82000) e os dados do trampolim dos APs. A
  IDT e a GDT do boot são carregadas pela VA do mapa direto (as pilhas dos
  APs são pilhas de kernel do MmCreateKernelStack, como a da thread ociosa
  que o KeStartAllProcessors cria para cada processador); MmMapIoSpace e os mapeamentos físicos da HAL
  devolvem VAs dele. Como o MiReferenceIoPages do NT, MmMapIoSpace(Ex)
  conta uma referência em cada página de I/O (não RAM) mapeada e o
  MmUnmapIoSpace a tira (`mm/io_space.rs`); o MmIsIoSpaceActive consulta
  essas referências.
- **Endereço virtual** é acessado por `mm/guest_memory.rs` (memória confiável
  ou sondada) ou pelos MOVs de `hal::volatile`.
- **Stubs em assembly** carregam a VA da página de IRQ num registrador
  (`movabs`) e endereçam por deslocamento; o estado da execução de usuário é
  por CPU e vem pelo `gs:` (o bloco por CPU, acima).
- O rastreador de frames não conta referências do mapa direto nem da janela
  do heap (nem da identidade temporária do trampolim).
- **Prova:** não existe identidade baixa para cair por engano: um endereço
  físico usado como ponteiro, um ponteiro truncado para 32 bits ou um
  ponteiro de kernel abaixo de MmSystemRangeStart falta no anel 0 e para o
  sistema com o diagnóstico.

**Heap do kernel e arena dos convidados.** Os frames de 32 MB a 96 MB, do
`kmalloc`, e os de 256 MB a 272 MB, da arena (o começo da faixa entre a
primeira e a segunda arena do PFN, que nenhuma delas usa), ficam fora do PFN
e aparecem só na janela do heap, `KERNEL_HEAP_BASE + (PA - 32 MB)`, o
papel do pool não paginado inicial do NT: páginas de 2 MB de supervisor, RW e
sem execução (NX), como o NonPagedPoolNx; os remapeamentos de páginas da
janela (o mapeamento reservado das MDLs) também ficam NX. Nada executa do
heap nem da arena: as rotinas que o kernel entrega aos caminhos nativos (a
rotina de kernel e de rundown das APCs de conclusão, o
KeSpecialUserApcKernelRoutine, a rotina de conclusão dos IRPs retidos) são
funções da imagem do kernel, chamadas pela ABI MS x64. Os tipos de pool
seguem o Windows 10 19041 (`ex/pool_allocation.rs`): o NonPagedPool (tipo 0,
o NonPagedPoolExecute) e o NonPagedPoolCacheAligned, pelo
ExAllocatePoolWithTag(Priority), ExAllocatePoolZero/Uninitialized e pelas
listas lookaside, e o ExAllocatePool2 com POOL_FLAG_NON_PAGED_EXECUTE saem de
regiões executáveis do pool executivo (`kernel_pool`, que nunca mistura
páginas executáveis e NX numa região); o NonPagedPoolNx (0x200), o
NonPagedPoolNxCacheAligned, o PagedPool e o ExAllocatePool2 com
POOL_FLAG_NON_PAGED ou POOL_FLAG_PAGED ficam NX. O código
que os autotestes geram (rotinas de drivers de teste, callbacks, corpos de
threads nativas) fica numa imagem carregada ou numa alocação executável da
janela de sistema, MmAllocateContiguousNodeMemory com PAGE_EXECUTE_READWRITE
(`ntos/test/executable_code.rs`). O autoteste `ntos/test/multiprocess/heap_nx.rs`
confere as páginas da janela sem execução e chama, de uma imagem de teste
numa execução nativa possuída, um endereço da arena com código: a busca da
instrução falta e vira STATUS_ACCESS_VIOLATION de execução
(ExceptionInformation[0] = 8), tratada pelo SEH da imagem; o mesmo código
numa alocação executável roda, assim como num bloco do
ExAllocatePoolWithTag/ExAllocatePoolZero(NonPagedPool) e do ExAllocatePool2
com POOL_FLAG_NON_PAGED_EXECUTE, e num bloco do NonPagedPoolNx ou do
ExAllocatePool2 com POOL_FLAG_NON_PAGED falta da mesma forma.
`paging::map_kernel_heap_window` monta a janela no boot, antes da primeira
alocação, com a PDPT e a PD fixas em 0x7B000-0x7CFFF. O `kmalloc` (e com ele
todo `Box`/`Vec` do kernel) e a arena de 16 MB, que não sai dos 64 MB dele
(numa máquina sem RAM na faixa da arena, menos de 272 MB, ela volta a ser um
bloco do heap reservado no boot, `hal/host.rs`), devolvem VAs
dessa janela: toda IRP, DEVICE_OBJECT, MDL, pool do ExAllocatePool2 e
estrutura NT que um driver recebe fica acima de MmSystemRangeStart, como os
drivers reais esperam ao comparar ponteiros com MmUserProbeAddress. Os
cabeçalhos são lidos e gravados pela VA; os links da arena são offsets a
partir da base dela. Quem precisa do endereço físico de um bloco (a tabela
PRD e o buffer de passagem do DMA ATA) traduz pelas tabelas de páginas. Os 32
bits baixos da base caem no buraco de MMIO acima de 3 GB, então um ponteiro
truncado para 32 bits falta. O teste
`ntos/test/system_allocations.rs`, no fim da fase 6, confere a arena, o heap,
o pool, IRPs, MDLs e os DRIVER_OBJECTs/DEVICE_OBJECTs vivos, inclusive os dos
drivers reais.

**Censo do heap.** Cada bloco ocupado do `kmalloc` guarda no cabeçalho o
índice do local que o pediu (`hal/heap_census.rs`): a cadeia de até oito
endereços de retorno, lida pelos frame pointers só dentro da pilha de kernel
corrente (StackLimit..StackBase da KTHREAD ou a pilha de boot). A tabela dos
locais fica em frames fixos fora do heap (`KERNEL_HEAP_CENSUS_PHYS`, 2 MB,
pelo mapa direto) e soma, por local, os bytes e blocos vivos e as alocações
feitas; só é tocada com o lock do heap, e um local sem blocos vivos é
reaproveitado por uma cadeia nova (a suíte vê mais cadeias do que cabem na
tabela). O censo vai para a serial
(`[heap-census]`) na falha do heap e, com `--heap-census` (a opção de carga
HEAPCENSUS), a cada 4 MB a mais de uso; `cargo xtask heap-census` dá os nomes
pelos símbolos do kernel.elf do build e soma os locais por função, e o
test-boot que falha com um censo na serial imprime esse resumo.

O que é grande não passa pelo heap, como no NT nada do tamanho de um arquivo
passa pelo pool: a seção de imagem lê as seções do PE do disco direto para
os frames protótipo da control area (também quando o arquivo vem de um
FILE_OBJECT de usuário; sem cópia direta, uma página por vez), o cache de
leitura dos arquivos do volume guarda os blocos em frames do PFN, os bins das
hives ficam em páginas do VirtualAlloc de kernel (o papel do pool paginado),
a ntdll de sistema vai do volume para os frames e as notificações a leem do
arquivo, e os arquivos embutidos ficam no RAMFS por referência. O Registro
não guarda nada por chave de hive no heap: o conteúdo de uma chave (nome,
valores, classe, LastWriteTime, subchaves) é lido das células a cada
consulta, e só as chaves em uso têm nó (o KCB: um handle aberto, uma
subchave viva, ou um dos 2048 da lista de fechamento adiado); a hive é
lida do arquivo um bin de cada vez, sem a imagem inteira no heap.

**Raízes e metade de sistema congelada.** Como no NT, a metade de sistema é
a mesma em todo espaço de endereçamento, e é compartilhada pelas entradas da
PML4:

- Na fase 0, logo depois do PFN e do mapeamento recursivo,
  `mm/process_address_space.rs::prepare_system_space` pré-aloca a PDPT de
  toda entrada de sistema da PML4 do boot que ainda falta e congela a metade
  (`paging::freeze_kernel_half`). [256] é a auto-referência e [257..512)
  apontam para PDPTs de supervisor (cerca de 1 MB do PFN), menos o slot de
  sessão [498], que fica vazio (veja o espaço de sessão).
- As PDPTs entram no conjunto `permanent` de `paging.rs`: nunca voltam ao
  PFN, nem quando a última página do slot é desfeita.
- Depois do congelamento, criar ou alterar uma entrada de sistema da PML4 é
  erro fatal (assert em `pd_entry_address`), e `map_page`/`map_large_page`
  recusam página de usuário na metade de sistema. O que o kernel mapeia
  depois só muda os níveis de baixo, em tabelas compartilhadas.
- Por isso uma raiz nova (`process_address_space::create_root`) copia
  PML4[257..512) uma única vez e fica coerente para sempre. Ela ganha a
  própria auto-referência em [256] e começa com a metade de usuário e o slot
  de sessão vazios.
  `delete_root` só a devolve ao PFN depois de desfeita a metade de usuário.
- Toda operação de `paging.rs` (query, translate, find, access, map, unmap,
  split, páginas de 2 MB) tem a forma `*_in(root, ...)`, que anda a partir
  da PML4 de endereço físico `root`. A forma sem raiz usa a raiz corrente,
  `paging::current_root()` (o CR3). Trocar a proteção de uma página é
  mapear o mesmo frame de novo com as flags novas, também por raiz.
- **Espaço de um processo.** `process_address_space::create(eprocess)`, o
  MmCreateProcessAddressSpace, chamado por `ps::process::create_process`
  para todo processo com imagem (o PspAllocateProcess: todo processo de
  usuário nasce com a raiz dele e roda nela; o System e os processos de
  kernel ficam na raiz do boot), dá ao processo uma raiz nova com a visão de
  usuário da KUSER_SHARED_DATA em 0x7FFE0000 (MM_SHARED_USER_DATA_VA): o
  mesmo frame da visão de kernel, U/S, somente leitura e sem execução,
  mapeado por `shared_user_data::map_user_view_in(root)`, o mesmo caminho
  que monta a visão na raiz do boot. A raiz vai para
  KPROCESS.DirectoryTableBase (UserDirectoryTableBase 0, sem KVA shadow) e
  para `ProcessState.directory_table_base`; o Mm guarda EPROCESS -> raiz.
- `process_address_space::delete(eprocess)`, o MmDeleteProcessAddressSpace,
  roda no último dereference do EPROCESS (`ps::process::collect_process`, o
  papel do PspProcessDelete). `paging::release_user_half_in` percorre a
  metade de usuário inteira e devolve ao PFN toda tabela dela, vazia ou não,
  e depois a raiz; o processo volta a apontar para a raiz do System. Uma
  página de usuário ainda mapeada fora da visão da KUSER faz o delete
  recusar sem mudar nada, e uma raiz carregada em alguma CPU também é
  recusada. O término desfaz antes toda folha de usuário do processo na raiz
  dele (`process_state::destroy`: VAD, módulos do loader, imagem principal e
  cópias de sistema), então o último dereference devolve a raiz inteira.
- **Troca de CR3** (`ke/context_switch.rs`, o KiSwapProcess). Fora da troca,
  o CR3 de cada CPU é o KPROCESS.DirectoryTableBase de
  `KTHREAD.ApcState.Process` da thread corrente. KeStackAttachProcess,
  KeAttachProcess e o escopo `ps/process_context.rs::with_process` carregam
  a raiz do destino quando ela difere da carregada;
  KeUnstackDetachProcess e KeDetachProcess, a do processo que o KAPC_STATE
  salvo devolve, então o aninhamento é o dos KAPC_STATE, como no NT. Como o
  KiAttachProcess, o attach reinicia só os campos do KAPC_STATE (0x2B bytes):
  o resto dos 0x30 do ApcState embutido é o KTHREAD (o Priority em +0xC3). A
  CPU também passa de um KPROCESS.ActiveProcessors para o outro. O attach
  recusa, antes de mexer no KAPC_STATE, um processo cuja raiz não é a do
  System nem uma raiz do Mm (`process_address_space::is_root`).
  `ps::process::set_current_thread`, o ponto único de troca de thread, carrega
  a raiz do processo corrente da nova thread e move a CPU em
  ActiveProcessors. Cada CPU registra o processo em que está
  (`context_switch::active_process`): a troca tira o bit dela do processo
  registrado, nunca do processo da thread que sai, que pode já ter sido
  liberada, e o último dereference de um processo o tira do registro
  (`forget_process`) antes de o EPROCESS voltar ao pool.
  `context_switch` registra a raiz carregada em cada CPU (`is_root_loaded`),
  e é por esse registro que o delete recusa uma raiz em uso. Só o BSP roda o
  anel 3 (assert na entrada) e carrega a raiz de um processo de usuário; os
  APs ficam na raiz do System. O mapeamento recursivo confere a
  auto-referência da raiz carregada, não a da PML4 do boot.
- **Rastreador de frames por raiz** (`mm/frame_mapping_tracker.rs`): além da
  árvore da PML4 do boot (a metade de sistema inteira e a metade de usuário
  do System), segue a de cada raiz de processo. `create_root` a registra
  (`add_root`: a auto-referência dela ganha a referência de tabela do frame
  da raiz, e a metade de usuário é seguida dali em diante; a metade de
  sistema, cópia da do boot, não é seguida de novo), e cada tabela sabe de
  que raiz é. As PDPTs, PDs e PTs de usuário de um processo e as folhas
  delas ganham referências no banco nativo de PFNs (ShareCount, PteAddress =
  o alias recursivo, válido com a raiz carregada, e PteFrame), como as do
  System. Uma tabela ou página ainda ligada não volta ao PFN, e um frame já
  livre também não: `release_user_half_in` e `delete_root` param o sistema se
  o PFN recusar uma tabela ou a raiz (ainda referenciada ou já livre), e
  `delete_root` recusa, sem mudar nada, uma raiz que ainda tem tabelas no
  rastreador (`remove_root`: uma desmontagem que esquecesse tabelas). O
  autoteste `ntos/test/multiprocess/process_tables.rs` cria um processo pelo
  caminho real e confere a raiz e as tabelas de usuário dele no rastreador,
  todas referenciadas, e o MMPFN da página da PEB; depois de rodar e do
  último dereference, nenhuma tabela dele sobra e as contagens de tabelas e
  de frames livres voltam às de antes. Numa raiz avulsa, a PT ligada e a
  página não podem voltar ao PFN, e o `delete_root` com a PML4E apagada por
  fora recusa por causa das tabelas esquecidas.
- **Assert de CR3** (`ke/context_switch.rs::check_loaded_root`, instalado em
  `guest_memory::set_root_check` no armar do anel 3, em todo boot): toda VA
  de usuário que o kernel toca, por acesso confiável (`guest::read/write`,
  os atômicos, `NtStruct::at` dos campos `Field`) ou sondado, exige que a
  raiz no CR3 desta CPU seja a do processo corrente da thread corrente dela
  (KPRCB.CurrentThread pelo GS, e dela `ApcState.Process`). A divergência
  para o sistema com a VA, as raízes e a linha do chamador.

O autoteste `ntos/test/multiprocess/page_table_root.rs` (fase 7) confere as
256 entradas presentes e permanentes, a PDPT de um slot vazio sobrevivendo a
um mapear/desfazer, a raiz do boot e a corrente dando a mesma resposta em
amostras das duas metades, e uma raiz nova com os mesmos frames de kernel,
sem páginas de usuário, que isola uma página mapeada nela.
`ntos/test/multiprocess/address_space.rs` (fase 7) cria os espaços de dois
processos: a raiz fica no KPROCESS e no `ProcessState`, a KUSER de usuário
está presente e somente leitura nos dois, a mesma VA de usuário cai em
frames diferentes e as VAs de kernel nos mesmos, o delete recusa com página
mapeada e depois devolve tudo (a contagem livre do PFN volta à de antes), e
o último dereference de um processo com espaço próprio o libera.
`ntos/test/multiprocess/attach_cr3.rs` (fase 7) anexa a um processo com
espaço próprio e lê e grava pela VA de usuário a página mapeada só nele;
desanexado, a mesma VA dá STATUS_ACCESS_VIOLATION na sonda. Também confere
que um attach aninhado e o KeAttachProcess restauram cada raiz, que a thread
corrente de outro espaço carrega a raiz dele e que o delete de um espaço
carregado é recusado. `ntos/test/multiprocess/own_root.rs` (fase 7) monta
dois processos de usuário ao mesmo tempo pelo caminho real
(`ps::create::create_user_process`): raízes próprias e distintas; a PEB e a pilha na
mesma VA nos dois, com conteúdo diferente lido anexado a cada um e frames
que a raiz do System não vê; a ntdll em cópias privadas na mesma VA. Depois
os dois rodam um depois do outro (`run_created`) com os próprios códigos de
saída, e no fim as raízes ficam só com a KUSER, voltam no último
dereference e o PFN livre volta ao de antes.

**Espaço de sessão** (`mm/session.rs`, `mm/session_pool.rs`,
`mm/session_image.rs`). Como no Windows 10 19041 x64, o espaço de sessão é
um slot inteiro da PML4 (512 GB, `memory_map::SESSION_SPACE_PML4_INDEX` =
498, o MM_SESSION_SPACE_DEFAULT clássico; o 19041 sorteia o slot e as faixas
dentro dele) que não é compartilhado entre as raízes:

- **Por sessão.** Cada sessão tem a própria tabela de topo (a PDPT do slot:
  MM_SESSION_SPACE.SessionPageDirectoryIndex é o PFN dela e PageDirectory é
  a entrada da PML4 que a aponta). A raiz de cada processo da sessão recebe
  essa entrada (`paging::set_session_top_level`, o MiSessionAddProcess) e a
  perde quando o processo sai (o MiDeleteTopLevelSessionMapping); a raiz do
  System e a de quem não tem sessão deixam o slot vazio. Como a PML4 é por
  processo, a troca de raiz na troca de thread e no attach já troca o
  espaço de sessão, sem passo a mais no `context_switch`; uma VA de sessão
  tocada fora de uma sessão (ou num AP, que fica na raiz do System) falta,
  como no NT. MmIsSessionAddress é o tipo do slot (MiVaSessionSpace). O
  rastreador de frames segue de cada raiz de processo só a metade de
  usuário e a auto-referência, então as tabelas e folhas de sessão ficam
  fora dele (sem PteAddress no banco nativo de PFNs).
- **Faixas** (`memory_map.rs`): SessionCore em +0 (o MM_SESSION_SPACE, 5
  páginas, na mesma VA em toda sessão), a VA dinâmica em +1 GB (128 GB: o
  pool paginado de sessão), as imagens de sessão em +129 GB (128 GB) e a
  lista do working set em +257 GB (reservada). A primeira página do
  MM_SESSION_SPACE também aparece numa VA global de sistema
  (`SESSION_GLOBAL_BASE..TOP`, o MiReservePtes de uma PTE do
  MiSessionCreateInternal), que é o EPROCESS.Session: id, contagens,
  ProcessList e flags são lidos de qualquer contexto; o PoolTags (+0x1000)
  só dentro da sessão.
- **Criação e fim.** PROCESS_CREATE_FLAGS_CREATE_SESSION cria a sessão
  (`session::create`, o MiSessionCreate: menor id livre, tabela de topo, as
  páginas do SessionCore, a VA global, NonPagablePages = CommittedPages = 8,
  LocaleId, CreateTime; o criador é o mestre, Vm.Flags.SessionMaster); os
  outros processos entram na sessão de quem os cria (`session::join`, o
  MiJoinSession), todos com EPROCESS.Flags.ProcessInSession. No
  PspProcessDelete o processo sai (`session::leave`); a última referência
  (MiDereferenceSessionFinal) descarrega as imagens de sessão, devolve o
  pool de sessão, desfaz o SessionCore e as tabelas e devolve a VA global e
  o id. As páginas de sessão são editadas por uma raiz de edição da sessão
  (uma PML4 com a metade de sistema e só esta sessão no slot, nunca
  carregada): as tabelas abaixo da de topo são as mesmas em toda raiz da
  sessão, então a edição vale em todos os processos dela sem anexar a
  ninguém; desfazer uma página de sessão invalida a TLB em todas as CPUs
  antes de o frame voltar ao PFN.
- **Attach.** `session::attach`/`detach` (MmAttachSession/MmDetachSession)
  contam AttachCount (sessão com DeletePending: STATUS_PROCESS_IS_TERMINATING)
  e fazem o KiStackAttachProcess num processo da sessão (quem já está nela
  anexa a si mesmo); `session::by_id` (MmGetSessionById) devolve um processo
  referenciado da sessão que não é o mestre, só depois de o driver de sessão
  registrar o DriverUnload (MmSessionSetUnloadAddress). MmGetSessionId(Ex) e
  MiGetSessionIdForVa também moram ali.
- **Pool de sessão** (`session_pool.rs`, chamado por `ex/pool_allocation.rs`):
  PagedPoolSession (33, 37) sai do heap da sessão do processo corrente, na
  VA dinâmica dela, residente; NonPagedPoolSession (32, 36, 544, 548) sai do
  pool não paginado global. Os dois contam na tabela de tags da sessão
  corrente (o PoolTags do MM_SESSION_SPACE, 0x100 POOL_TRACKER_TABLE com o
  hash e os bytes do ExAllocateHeapPool). Fora de uma sessão o pedido é
  recusado; liberar uma VA de sessão que a sessão corrente não alocou para
  com BAD_POOL_CALLER (0, 0, VA, 0), o do ExFreeHeapPool quando o heap da
  sessão não acha o segmento. O fim da sessão leva o heap inteiro.
- **Imagens de sessão** (`session_image.rs`, MmLoadSystemImage com
  MM_LOAD_IMAGE_IN_SESSION, que exige ProcessInSession, senão
  STATUS_NO_MEMORY): o `pe_loader` carrega a imagem uma vez na faixa de
  imagens de sessão, e os frames dela (relocados, com a IAT e o cookie) são a
  cópia mestra; cada sessão que a carrega mapeia o código e as páginas
  somente leitura sobre os frames mestres, sem escrita, e as graváveis sobre
  cópias privadas feitas na carga (o copy-on-write dos protótipos por sessão
  já resolvido, como o NT faz com as seções NOT_PAGED, que são todas as
  graváveis do win32k*.sys e do cdd.dll). A segunda sessão recebe a mesma VA
  e a mesma entrada do loader (LoadCount + 1); MmUnloadSystemImage tira a
  imagem só da sessão corrente e a última sessão a descarrega. As
  dependências seguem o resolvedor global. As imagens de sistema não mudam.
- Teste: `ntos/test/multiprocess/session_space.rs` (fase 7), duas sessões
  criadas pelo caminho real e o BOOTVID.DLL real carregado nas duas.

**Imagens.**

- **Imagens de kernel** (drivers .sys, hal.dll, ci.dll, bibliotecas de export
  como cng, msrpc, wmilib e WppRecorder): janela `SYSTEM_IMAGE_BASE..TOP`
  (0xFFFFF801_00000000..0xFFFFF802_00000000). O `pe_loader` faz o papel do
  MiLoadSystemImage: reserva a faixa (primeiro encaixe, 64 KB), copia a imagem
  para frames do PFN não contíguos, mapeia em PTEs de 4 KB de supervisor e
  reloca pela diferença para a ImageBase do cabeçalho. Imagem sem relocações
  (`IMAGE_FILE_RELOCS_STRIPPED`) é recusada com STATUS_CONFLICTING_ADDRESSES.
  No descarregamento, a VA e os frames só voltam ao uso depois da invalidação
  de TLB em todas as CPUs. Nenhuma imagem de kernel fica na metade de
  usuário; o ntoskrnl não passa pelo loader (o stage2 já o mapeia na sua
  ImageBase) e é listado ali.
- **NtLoadDriver e NtUnloadDriver** (`io/driver_load.rs`, adaptadores em
  `ps/user/device_io.rs` e nos exports Zw*): o IopLoadDriverImage e o
  IopUnloadDriver do 19041. Em modo usuário, o SeLoadDriverPrivilege do
  token efetivo (o services.exe impersona uma cópia do próprio token com o
  privilégio habilitado) e a captura do nome; o LOAD_PACKET vai a uma worker
  do sistema e quem chama espera o evento (direto quando quem chama já é o
  processo System). A carga abre a chave pelo nome completo (uma chave
  ausente dá STATUS_OBJECT_NAME_NOT_FOUND), monta o caminho da imagem como
  o IopBuildFullDriverPath, dá STATUS_IMAGE_ALREADY_LOADED com o objeto já
  publicado, devolve o status do DriverEntry quando ele falha e roda as
  rotinas de reinicialização; o kernel não inicia o DependOnService. A
  descarga recusa com STATUS_INVALID_DEVICE_REQUEST um driver sem
  DriverUnload, sem imagem ou PnP (com AddDevice).
- **Drivers carregados por outro driver** (o KMDF): a WdfLdr.sys é um driver
  de export, carregado pelo `mm/sysload.rs` como biblioteca de import do
  cliente KMDF; o WdfVersionBind do cliente pede o ZwLoadDriver do serviço
  do runtime (Wdf01000), que sobe pelo NtLoadDriver em KernelMode
  (`io/driver_load.rs` → `io/lifecycle.rs`) aninhado no DriverEntry do
  cliente: `lifecycle::load_driver` guarda e devolve o driver corrente. O
  ImagePath de um serviço pode ser relativo, e então é relativo ao
  \SystemRoot (`system32\drivers\Wdf01000.sys`); System32\Drivers fica na
  raiz do volume.
- **O nome do DRIVER_OBJECT** (`io/driver_load.rs`, o
  IopGetDriverNameFromKeyNode): o ObjectName REG_SZ da chave do serviço,
  quando existe; senão `\FileSystem\<chave>` para os tipos 2 (file system) e
  8 (reconhecedor) e `\Driver\<chave>` para os outros, com o nome da chave
  como está na hive. Um driver sem chave fica em `\Driver\<nome>`. O
  `lifecycle` guarda o nome de cada driver e o acha pelo nome do serviço
  (`lifecycle::driver_node`); as chaves de driver semeadas não têm
  ObjectName, como as da instalação, e o services.exe confere o estado de um
  driver pelo mesmo nome no `\Driver` ou no `\FileSystem`.
- **Imports entre imagens de kernel** (`mm/pe_loader.rs`, `mm/sysload.rs`),
  como no MmLoadSystemImageEx: a entrada da imagem entra na lista de imagens
  carregadas (a PsLoadedModuleList) depois da relocação e antes dos imports,
  com o bit LOAD_IN_PROGRESS (0x1000) das Flags ligado enquanto a IAT é
  resolvida. Um import que volta a uma imagem em carga (o netio.sys e o
  ndis.sys importam um do outro) acha essa entrada pelo BaseDllName e usa os
  exports dela, sem reter referência (o LoadCount não sobe). Uma DLL carregada
  pelo import ganha DRIVER_DEPENDENT_DLL (0x04000000) e o DllInitialize logo
  depois da própria carga, antes de o importador seguir para o import
  seguinte (MiLoadImportDll -> MmCallDllInitialize), com o caminho
  `...\Services\<BaseDllName até o primeiro ponto>`. Um `.sys` importado com
  ponto de entrada e sem DllInitialize sobe como driver pelo lifecycle
  (mapeado uma vez); o tipo da imagem é decidido pelos exports lidos do
  arquivo. O FullDllName é o caminho NT da imagem, não o da fonte dos bytes:
  o ImagePath do serviço (relativo a `\SystemRoot`) para um driver iniciado
  pelo SCM, `\SystemRoot\System32\drivers\<nome>` para um `.sys` carregado
  pelo import e `\SystemRoot\System32\<nome>` para uma DLL de kernel; a CI
  abre o arquivo pelo nome da fonte. Um encaminhamento de export de kernel
  não traz a extensão ("NDIS.NdisMatchPdoWithPacket"): como no MiSnapThunk,
  vale a imagem carregada cujo BaseDllName começa com "<módulo>.".
- **PsLoadedModuleList e PsLoadedModuleResource** (`mm/loaded_images.rs`) são
  exports de dado: a cabeça LIST_ENTRY e o ERESOURCE moram na `.kdata` do
  kernel (`mm/kernel_data_layout.rs`). A fase 0, logo depois de o System
  existir, inicializa o recurso e liga a lista às KLDR_DATA_TABLE_ENTRY já
  registradas (ntoskrnl primeiro, depois a HAL e os drivers, na ordem de
  registro); cada carga, descarga, ocultação ou troca de Flags refaz a lista
  com o recurso exclusivo e a região crítica (como o MiProcessLoaderEntry),
  e quem percorre a lista (depuradores, antivírus, anti-cheat) a lê sob o
  recurso compartilhado. Antes da publicação, fora de uma thread ou acima de
  APC_LEVEL vale só a trava do registro.
- As imagens de usuário ficam na ImageBase do cabeçalho quando a faixa está
  livre na metade de usuário (ou na primeira faixa livre a partir de 64 KB,
  relocadas), também sobre frames do PFN.

### 3.5 Plug and Play e as pilhas reais de armazenamento e de vídeo

A árvore de dispositivos do NT mora em `ntos/io/pnp/`:

- `devnode.rs`: um DEVICE_NODE por PDO (ids, caminho da instância em
  `Enum`, capacidades, barramento, configuração de boot, requisitos,
  recursos brutos e traduzidos, serviço, estado e o CM_PROB_* que parou o
  nó). A raiz é `HTREE\ROOT\0`, sobre um PDO do PnpManager.
- `irp.rs`: o IopSynchronousCall. Todo pedido vai ao topo da pilha com
  IoStatus.Status = STATUS_NOT_SUPPORTED e Information inicial (a lista no
  FILTER_RESOURCE_REQUIREMENTS); o pool que o driver devolve volta pelo
  ExFreePool.
- `tree.rs`: o PipProcessDevNodeTree. Para cada PDO novo das BusRelations:
  QUERY_ID (DeviceID), QUERY_CAPABILITIES, InstanceID (sem UniqueID, com o
  ParentIdPrefix `nível&hash&n` do PipMakeGloballyUniqueId; o hash confere
  com o `3&267a616a&0` de um Windows nesta VM), HardwareIDs, CompatibleIDs,
  textos, QUERY_BUS_INFORMATION, QUERY_RESOURCES e
  QUERY_RESOURCE_REQUIREMENTS; a chave da instância; a instalação; os
  AddDevice (LowerFilters da instância e da classe, serviço, UpperFilters);
  FILTER_RESOURCE_REQUIREMENTS, arbitragem e tradução; START_DEVICE com as
  duas listas; QUERY_CAPABILITIES e QUERY_PNP_DEVICE_STATE; enumeração. O
  PnP marca cada PDO que um barramento relata com DO_BUS_ENUMERATED_DEVICE.
  Um nó instalado com o driver nulo (classe sem serviço, as seções NO_DRV
  do machine.inf) inicia cru, só com o PDO, se o barramento o declara
  RawDeviceOK (a ponte de host do pci.sys, os PNP0A06, o PNP0B00, o
  ACPI0010 e o botão de função fixa do acpi.sys), e fica sem iniciar, sem
  problema, se não (o HPET), como o PipCallDriverAddDevice. O
  IoInvalidateDeviceRelations de um nó da árvore (BusRelations ou
  SingleBusRelations, como o PnpRequestDeviceAction) enfileira a
  reenumeração: dentro do `process` a fila é drenada ali; fora dele, o
  pedido põe o PnpDeviceActionWorker na fila de trabalho atrasada, que a
  drena (o volume que o volmgr.sys relata ao receber uma partição do
  partmgr.sys chega assim, de um work item).
- `install.rs`: as linhas de modelo dos INFs da caixa que atendem o
  hardware emulado (mshdc.inf, disk.inf, volume.inf, volmgr.inf, o
  display.inf com o BasicDisplay.sys para PCI\CC_0300, o basicrender.inf
  com o BasicRender.sys para ROOT\BASICRENDER, o monitor.inf com o
  monitor.sys (KMDF) para os monitores que o dxgkrnl relata
  (MONITOR\Default_Monitor e *PNP09FF) e o machine.inf com
  o msisadrv.sys para PCI\CC_0601 e o driver nulo das seções NO_DRV), com
  o serviço, a classe, os AddReg e o ExcludeID de cada seção. O posto segue o instalador (HardwareIDs antes
  de CompatibleIDs): PCI\VEN_8086&DEV_7010 instala o intelide.sys antes do
  pciide.sys de PCI\CC_0101. O ServiceBinary de um driver do repositório
  de drivers (`%13%`, como o BasicDisplay.sys) vai inteiro para o
  ImagePath (`\SystemRoot\System32\DriverStore\FileRepository\...`),
  que o carregador resolve sob o `\Windows` do volume do kernel
  (`\Device\KernelVolume1\Windows`, o destino de `\SystemRoot`).
- `arbiter.rs`: os árbitros e tradutores dos drivers de barramento, como o
  IopSetupArbiterAndTranslators. Para cada requisito, o PnP sobe a árvore
  perguntando a cada ancestral pelo árbitro do tipo (IRP_MN_QUERY_INTERFACE,
  GUID_ARBITER_INTERFACE_STANDARD, Size 0x30, o tipo no
  InterfaceSpecificData; um árbitro ARBITER_PARTIAL, como os do pci.sys,
  responde ao ArbiterActionQueryArbitrate se o pedido cabe nas janelas da
  ponte) e, a partir do próprio nó, pelo tradutor
  (GUID_TRANSLATOR_INTERFACE_STANDARD, Size 0x34), que abaixo do árbitro
  traduz o requisito (TranslateResourceRequirements). As respostas ficam por
  nó e tipo. A atribuição de uma lista alternativa é a do
  IopTestConfiguration/IopCommitConfiguration: os ARBITER_LIST_ENTRY de
  cada árbitro vão ao ArbiterHandler com TestAllocation e, se todos aceitam,
  CommitAllocation (senão RollbackAllocation e a próxima lista). O recurso
  bruto volta pelos tradutores abaixo do árbitro (ParentToChild) e o
  traduzido sobe por todos até um STATUS_TRANSLATION_COMPLETE. A liberação
  é o pedido nulo do PDO a cada árbitro. Com a raiz ACPI, as portas, a
  memória e os números de barramento das funções PCI e dos dispositivos ISA
  são do árbitro do pci.sys (as janelas do _CRS do PCI0), as IRQs são do
  árbitro do acpi.sys na raiz ACPI (o _PRT e os dispositivos de link ficam
  com ele) e o tradutor de interrupções do acpi.sys dá o vetor do IDT e o
  IRQL que o árbitro escolheu; o tradutor de ponte do acpi.sys traduz as
  portas e a memória do barramento PCI.
- `resources.rs`: as listas do NT, os árbitros da raiz (os IopRoot*Arbiter:
  primeira opção livre, alternativas, compartilhamento, sem janelas de
  barramento) e o tradutor da raiz: sem ACPI, a HAL traduz a IRQ de linha
  `n` para o vetor `0x20 + n`, IRQL `n`; com a raiz ACPI, a identidade. O
  IoReportResourceUsage (`io/legacy_resources.rs`, o
  IopLegacyResourceAllocation com ArbiterRequestLegacyReported) relata os
  recursos de um dispositivo ou driver legado como requisitos fixos aos
  árbitros da raiz: livres, ficam com ele; ocupados, STATUS_CONFLICTING_
  ADDRESSES e ConflictDetected; a lista vazia os libera. O desvio do NT
  para o barramento legado do tipo de interface da lista
  (IopFindLegacyBusDeviceNode) ainda não existe.
- `root.rs`: o barramento raiz; o barramento PCI interno
  (`drivers/bus/pci.rs`, PCI_HAL\PNP0A03\0) é filho dele. Ele mede cada
  BAR com a decodificação de I/O e de memória e o bus master desligados no
  comando, como o PciPreScanDisconnectDevice do pci.sys: com 1s, o BAR
  responderia no topo dos 4 GB, por cima da ROM do BIOS. Um
  IoReportDetectedDevice com a árvore montada vira um devnode
  `ROOT\<serviço>\NNNN` já iniciado.
- `device_api.rs`: o driver embutido `\Driver\DeviceApi` que o
  IopInitializePlugPlayServices cria em todo boot (PiDaInit, pelo
  IoCreateDriver): o PiDaDriverEntry põe o PiDaDispatch em CREATE, CLOSE,
  DEVICE_CONTROL e CLEANUP, uma FAST_IO_DISPATCH de 0xE0 bytes com o
  FastIoDeviceControl e cria o `\Device\DeviceApi`. O nome aberto abaixo
  dele escolhe o tratador da IrpHandlingTable (`\Dev\Query`,
  `\Dev\NoState`, `\CMApi`, `\SwDevice`, `\CMNotify`), guardado no
  FsContext; as rotinas do driver são stubs de `hal/amd64/routine_stubs.rs`.
- `cm_api.rs`: o `\CMApi` do cfgmgr32.dll (PiCMDispatch e
  PiCMHandleIoctl). Os IOCTLs (CTL_CODE(0x47, 0x200 + n, METHOD_NEITHER))
  só chegam pelo Fast I/O, com o pedido de objeto capturado
  (PiCMCaptureObjectInputData) e o resultado gravado no buffer de saída
  ({tamanho, status, ...}): GetDeviceStatus (DN_* e problema pelo nó),
  ValidateDeviceInstance (CM_Locate_DevNode), GetDeviceDepth e
  GetRelatedDeviceInstance sobre a árvore de `devnode.rs`;
  GetObjectProperty (DEVPROPKEY) e GetRegistryProperty (CM_DRP_*) sobre
  `io/device_property.rs`: na segunda, os valores da chave da instância
  (o texto indireto do INF resolvido), as propriedades do PnP pelo devnode,
  EnumeratorName pelo nome, Class pela classe de instalação do ClassGUID e
  as da classe pelo GUID (chave da classe e subchave Properties), com as
  recusas do _CmGetDeviceRegPropWorker; os demais códigos conhecidos ainda
  respondem STATUS_NOT_IMPLEMENTED.
- `cm_notify.rs`: o `\CMNotify` (PiUEventDispatch e PiUEventHandleIoctl),
  por onde o CM_Register_Notification do cfgmgr32 registra o interesse em
  interfaces e dispositivos. O registro (0x470800) cria um nome WNF
  temporário de escopo de máquina, devolve o nome e guarda o contexto no
  FsContext2; o fim do registro e o CLOSE o desfazem (o CLOSE apaga o nome
  pelo ZwDeleteWnfStateName de kernel). A entrega de eventos (GetEvent e
  Veto) e o filtro por handle de dispositivo ainda não têm suporte.

Os PDOs do barramento PCI respondem como o pci.sys (`drivers/bus/pci_pnp.rs`
e `pci_interface.rs`): ids, capacidades, requisitos dos BARs (sem os do canal
IDE legado; um BAR pré-buscável com CM_RESOURCE_MEMORY_PREFETCHABLE),
BUS_INTERFACE_STANDARD (o GetBusData/SetBusData acessa a configuração para
todo DataType menos o da ROM, como o pci.sys, que só aponta ao Driver
Verifier um DataType diferente de PCI_WHICHSPACE_CONFIG: o storport.sys passa
o PCIConfiguration do miniport) e PCI_BUS_INTERFACE_STANDARD,
READ/WRITE_CONFIG. As rotinas que um driver recebe por ponteiro (interfaces
de barramento, DMA_OPERATIONS) são stubs nativos de `hal/amd64/
routine_stubs.rs` (ids privados 0x80000400+). O adaptador de DMA é o da HAL
(`hal/dma.rs`: o HalGetAdapterV2 com a tabela V2 de operações e, para uma
DEVICE_DESCRIPTION da versão 3, o HalGetAdapterV3 com a largura de endereço
do DmaAddressWidth e a tabela V3 de `hal/dma_v3.rs`, descrita abaixo com a
pilha USB), alcançado pelo IoGetDmaAdapter
através da interface do barramento. Como o HalGetAdapterV2 do 19041, um bus
master sem scatter/gather, ou um de 32 bits (sem Dma64BitAddresses) numa
máquina com RAM acima de 4 GB, recebe registradores de mapa
(`hal/dma_map_registers.rs`): entradas de tradução com páginas de passagem
abaixo de 4 GB, num pool próprio montado no HalGetAdapter (contíguo, um
bitmap, ou de scatter, uma pilha) e no do adaptador mestre (o buffer de boot
de 64 KB, ou 192 KB com RAM acima de 4 GB, abaixo de 2 GB). O canal
(AllocateAdapterChannel/IoFreeAdapterChannel) serializa os WAIT_CONTEXT_BLOCKs
e entrega o MapRegisterBase; quem não acha registradores espera na fila do
mestre até um FreeMapRegisters. O MapTransfer de uma página acima do limite
usa o buffer (a escrita copiada na hora), o FlushAdapterBuffers devolve a
leitura, e a lista de scatter/gather desses adaptadores é montada pelo
MapTransfer num contexto (a lista em +0x30) quando o canal sai, com o
PutScatterGatherList esvaziando os buffers. IoGetDeviceProperty,
IoOpenDeviceRegistryKey, IoRegisterDeviceInterface (links
`\??\<instância>#{guid}`) e o IoConnectInterruptEx LINE_BASED leem o
devnode; o MESSAGE_BASED, sem interrupções por mensagem atribuídas, conecta
a linha com o FallBackServiceRoutine e devolve Version = CONNECT_LINE_BASED,
como o IoConnectInterruptEx do NT. O FILTER_RESOURCE_REQUIREMENTS parte com
STATUS_SUCCESS e a lista (o IopFilterResourceRequirementsCall), e o
barramento que não o trata devolve esse sucesso a quem repassou.

A árvore sobe uma vez no fim da fase 1 (`drivers/bus/device_tree.rs`,
`build`): o que cada pilha pedida precisa antes dela (os setores de
referência, o Registro e os drivers de boot da pilha de armazenamento; o
vídeo de boot), a raiz, o processamento da árvore inteira e as
conferências de cada pilha. A raiz é a ACPI (abaixo); com
`--pnp-root=internal`, `prepare` monta a raiz com o barramento PCI interno
e deixa com nó do kernel (sem instalação nem AddDevice, como um dispositivo
com driver de boot) as funções que um driver interno já serve naquele
boot: a controladora IDE sem `--storage=real` (o driver ATA interno serve o
volume do boot) e o adaptador VGA sem `--display=basic` (o console em modo
texto). As demais funções seguem o caminho comum; a ponte PCI-ISA recebe o
msisadrv.sys, um driver KMDF, e passa pelo AddDevice e pelo START do
framework.

Com `--storage=real` (`drivers/storage/storage_stack.rs`) sobe a pilha IDE
real nos nós que o pci.sys relata: intelide.sys/pciidex.sys na
controladora, atapi.sys/ataport.sys nos canais (as IRQs 14 e 15 pelo
árbitro e pelo tradutor do acpi.sys), disk.sys/classpnp.sys nos discos. O
adaptador de DMA chega ao pciidex pela BUS_INTERFACE_STANDARD que o
acpi.sys pede ao AcpiRootPdo (`hal/pnp.rs`, o HalpQueryInterface, com o
HalPnpGetDmaAdapter).

Com `--storage=nvme` (`drivers/storage/nvme_stack.rs`) o QEMU ganha um
controlador NVMe (`-device nvme`, PCI\VEN_1B36&DEV_0010, classe 01.08.02)
com o disco particionado que o xtask monta (`nvme.img`: MBR com uma
partição NTFS a partir do LBA 2048, volume do mesmo formato do `ntfs.img`
com o HiddenSectors da partição). O pci.sys real enumera o controlador sob
a raiz ACPI (com `--pnp-root=internal`, o barramento PCI interno), e o
stornvme.inf dá o stornvme.sys ao PCI\CC_010802 (classe SCSIAdapter, com
os valores do serviço e do hardware da seção); o storport.sys, que ele
importa, é o driver de porta. O partmgr.sys e o volmgr.sys carregam antes
da árvore do boot; o IoReportDetectedDevice do DriverEntry do volmgr cria
na hora o devnode ROOT\VOLMGR\0000 sob a raiz do PnP, que ele monta se
ainda não existe (no NT o nó raiz existe desde o IoInitSystem), e o
IoRegisterDeviceInterface do AddDevice acha a instância. No
FILTER_RESOURCE_REQUIREMENTS o storport repassa ao PDO e chama o filtro do
miniport (grupos e processadores, que o HwFindAdapter exige); no START o
HwFindAdapter acha o BAR0 nas AccessRanges e lê a configuração pela
interface do barramento, o storport cria o adaptador de DMA da versão 3 (o
miniport prefere o DMA v3) e a extensão não cacheada (MmAllocateContiguousNodeMemory),
o miniport habilita o controlador e faz os Identify pela fila de
administração (por varredura), e as interrupções vêm do IoConnectInterruptEx
MESSAGE_BASED: como o stornvme.inf pede MSISupported, o pci.sys pede
mensagens MSI-X e o árbitro de IRQ do acpi.sys as atribui (duas com uma
CPU: a da fila de administração e a da fila de E/S). O storport monta o
mapa de processador para mensagem pelo IoGetAffinityInterrupt de cada
objeto de mensagem (o processador do objeto, que recebe as mensagens), e o
stornvme põe cada pedido de E/S na fila da mensagem que o storport dá ao
processador corrente; sem mensagens, o recuo é a linha INTx (a GSIV e o
vetor que os árbitros atribuíram, pelos dados de conexão do PDO). Um relatório de dispositivo
falho que o storport faz ao WHEA (WheaReportHwErrorDeviceDriverEx com
severidade fatal) é registrado, sem parar a máquina, como no NT. O teste
lê o setor 0 pela pilha do disco (`NVME_DISK_OK`). O partmgr.sys entrega a
partição ao volmgr.sys (o IoGetDeviceObjectPointer no link de interface do
volmgr acha o PDO no FILE_OBJECT, o PmGivePartition manda o IOCTL), que cria
o `\Device\HarddiskVolume1` e relata o devnode STORAGE\Volume por
SingleBusRelations; no START o volmgr apaga o IsDeleted da chave de
hardware do volume com RtlDeleteRegistryValue(RTL_REGISTRY_HANDLE), que,
como o RtlCreateRegistryKey e o RtlWriteRegistryValue, usa a chave do
handle sem fechá-la. O devnode do volume é instalado pelo volume.inf com o
volume.sys (no bundle, como o volmgr.sys), sem os filtros de classe que
uma instalação acrescenta à classe Volume (volsnap, fvevol, rdyboost,
iorate). Com o volume iniciado, o mountmgr.sys recebe a chegada da
interface do volume (MountMgrMountedDeviceArrival: nome, identificador
único, IOCTL_VOLUME_GET_GPT_ATTRIBUTES) e, como a rotina de
reinicialização dele (MountMgrDriverReinitialization, depois dos drivers
de sistema) já ligou a atribuição automática, dá ao volume a primeira
letra livre: grava `\DosDevices\E:` no MountedDevices e cria o
`\GLOBAL??\E:`. O WorkerThread que ele enfileira (`QueueWorkItem`) abre o
`\Device\VolumesSafeForWriteAccess` e espera o smss sinalizá-lo antes de
reconciliar os bancos de pontos de montagem; sem smss a espera não
termina, como no NT, mas prende só uma worker thread do sistema. O
ntfs.sys monta a partição (`NVME_VOLUME_OK`): lê o arquivo que o xtask
gravou e grava, fecha, reabre e lê de volta um arquivo novo por `\??\E:`.
No caminho, o FsRtlNotifyVolumeEventEx do ntfs.sys pergunta o PDO do
volume (IoGetRelatedTargetDevice, IRP_MN_QUERY_DEVICE_RELATIONS
TargetDeviceRelation) e a lista que o driver devolve volta ao pool dele
pelo ExFreePool, como no PnpGetRelatedTargetDevice. Com 4 GB de RAM o
SeaBIOS põe o BAR0 de 64 bits acima de 4 GB, fora do mapa direto que o
MmMapIoSpace usa; o teste roda com 3 GB, e o BAR fica na janela de 32 bits.

O volume E: do NVMe é um volume PnP completo: o modo usuário o enumera
pelas mesmas APIs do Explorer e do ShellHWDetection. O teste e-process
(`ntos/test/volume_enumeration.rs`, `E_VOLUMES_OK`) roda um programa Win32
gravado no E: (o kernel32 e o cfgmgr32 reais do System32, numa sessão
nova; o volume desse escopo leva os programas de modo usuário do boot do
smss) que confere o
FindFirstVolumeW/FindNextVolumeW com o GetVolumePathNamesForVolumeNameW
(os IOCTLs do mountmgr.sys), o GetLogicalDrives (o mapa de devices DOS do
processo) e o CM_Get_Device_Interface_ListW de GUID_DEVINTERFACE_VOLUME (o
`\CMApi` do PnP manager, a interface que o volmgr.sys registrou no devnode
STORAGE\Volume).

**O volume do sistema no ntfs.sys (`--volume-sistema=ntfs.sys`, plano).**
Hoje o C: da cadeia é o NTFS do próprio kernel (`\Device\KernelVolume1`
sobre o driver ATA interno), sem devnode STORAGE\Volume nem interface de
volume. O alvo é o C: servido pela pilha real (atapi.sys e ataport.sys,
disk.sys e classpnp.sys, partmgr.sys, volmgr.sys e volume.sys,
mountmgr.sys) e pelo ntfs.sys, com o NTFS do kernel no papel do winload:
ler, antes da árvore de dispositivos, o que o carregador do NT entrega no
loader block, e nada depois. O NTFS do kernel continua o padrão até a
cadeia inteira passar com a opção. As decisões:

1. **O disco.** O segundo disco IDE (o `ntfs.img`) passa a ser
   particionado, como o `nvme.img` (MBR e uma partição NTFS a partir do LBA
   2048, o volume com o HiddenSectors dela), e a controladora fica com o
   atapi.sys (`--storage=real`). O winload do NT lê o volume de boot pelo
   firmware do mesmo disco que o kernel depois serve pelo driver de
   armazenamento; aqui o driver ATA interno faz o papel do firmware. O NVMe
   fica como disco de dados: o NTFS do kernel não tem como lê-lo antes da
   pilha real.
2. **O NTFS do kernel só lê, e só até a árvore.** Na fase 1 ele monta a
   partição pelo deslocamento dela, somente leitura nesse modo; dele vêm as
   hives da máquina (em memória, como as do loader block), as tabelas NLS,
   o errata.inf, os catálogos e as imagens dos drivers que sobem antes da
   árvore (acpi.sys, pci.sys, Wdf01000.sys, msisadrv.sys, cng.sys, ci.dll,
   ksecdd.sys, clfs.sys, clipsp.sys, fltmgr.sys, ntfs.sys). Quando o
   atapi.sys assume a controladora, o driver ATA interno para de vez e
   recusa qualquer comando.
3. **A troca.** No PnpBootDeviceWait do IopInitializeBootDrivers
   (`io/boot_partition.rs`), o volume da partição de boot recebe
   DO_SYSTEM_BOOT_PARTITION e o C: pelo IOCTL_MOUNTMGR_BOOT_DL_ASSIGNMENT;
   o IopReassignSystemRoot aponta o `\SystemRoot` e o `\Device\BootDevice`
   para `\Device\HarddiskVolume1\Windows`. Daí em diante todo arquivo do
   sistema é aberto pelo I/O Manager e servido pelo ntfs.sys, e as seções
   sobre eles são as de arquivo de file system (`mm/section/fsd_file.rs`,
   com a CONTROL_AREA no FCB e o writer de páginas mapeadas).
4. **Nada usa o trait `FileSystem` do volume do kernel depois da troca.**
   Mudam para FILE_OBJECTs e IRPs: as hives (`cm/hive_file.rs`: o
   CmpFileRead, CmpFileWrite, o tamanho e o flush por Zw nos handles, com a
   reassociação das hives carregadas aos arquivos do C:, como o
   CmpInitializeHiveList), as imagens de kernel (`mm/sysload.rs`, por seção
   de imagem sobre o arquivo, como o MmLoadSystemImage), a criação de
   processo e as cópias de sistema da ntdll e do apiset (`ps/create.rs`,
   `ps/user/loader.rs`, por seção sobre o arquivo do C:), as NLS
   (`ps/user/nls.rs`, `rtl/*_code_page.rs`, do loader block), o pool
   paginado e a paginação das imagens (`mm/kernel_pool.rs`,
   `mm/image_paging.rs`: pelo arquivo de paginação ou desligados nesse
   modo), `io/reparse.rs`, `em/mod.rs`, `ob/objects/file.rs` e
   `kd/explore.rs`.
5. **Os serviços de arquivo do modo usuário sobre arquivos de file
   system.** Já vão por IRP a leitura e a escrita, as consultas e o set
   information, as classes de volume, o notify, os locks e o flush. Faltam
   o NtQueryDirectoryFile(Ex), o NtDeleteFile, renomear e ligar (o
   IopOpenLinkOrRenameTarget com SL_OPEN_TARGET_DIRECTORY), o STATUS_REPARSE
   e os EAs no IRP_MJ_CREATE e a ApcRoutine do I/O de dispositivo.
6. **A segurança dos arquivos.** O ntfs.sys confere o descritor de cada
   abertura; a imagem precisa dos descritores de uma instalação (herança
   OI/CI e ALL APPLICATION PACKAGES) antes de a cadeia rodar nele, senão os
   processos AppContainer não abrem nada.
7. **O arquivo de paginação** no C: pelo ntfs.sys: o NtCreatePagingFile já
   segue o MiCreatePagingFile; falta o PpPagePathAssign
   (DEVICE_USAGE_NOTIFICATION à pilha do volume).

Os marcos, cada um com um teste:

- **S0** (`SYSTEM_VOLUME_NTFS_OK`): com `--volume-sistema=ntfs.sys`, o disco
  particionado, o NTFS do kernel lendo a partição na fase 1, a pilha IDE
  real, o volume da partição com o C: pelo BOOT_DL_ASSIGNMENT e o ntfs.sys
  montado nele; arquivos do `\SystemRoot` lidos pelo ntfs.sys conferem com
  os do NTFS do kernel.
- **S1** (`SYSTEM_VOLUME_SWITCHED_OK`): o IopReassignSystemRoot e o fim do
  NTFS do kernel (item 4), sem nenhum comando ao driver ATA interno depois
  do atapi.sys.
- **S2** (`SMSS_CSRSS_OK` com o C: no ntfs.sys): smss, KnownDlls, csrss e
  wininit; os serviços do item 5.
- **S3** (`LOGON_SCREEN_OK` e `DESKTOP_OK`): winlogon, services, LSA, a hive
  do usuário e o explorer; os descritores do item 6.
- **S4**: barra-de-tarefas, area-de-trabalho, gerenciador-de-tarefas e
  bloco-de-notas passam com a opção; só então ela pode virar o padrão.

O que já existe do S0 (teste `volume-sistema`, `SYSTEM_VOLUME_NTFS_OK`):
o xtask grava o volume do sistema numa partição do segundo disco
(`ntfs_image::build_system_disk`) e liga `--storage=real`; o NTFS do kernel
acha a partição NTFS pelo MBR e soma o começo dela só na E/S ao disco (o
campo `base` de `drivers/fs/ntfs.rs`; os LBAs dos runs e das escritas
pendentes continuam relativos ao volume); a fase 1 sobe o cng.sys, a CI e a
árvore de dispositivos logo depois dos drivers de boot, antes das rotinas
de reinicialização deles, e inicia o ntfs.sys (driver de boot do grupo
"Boot File System"); as mudanças de interface de volume ficam retidas
durante essa árvore (`io/pnp_notify.rs`, o papel da fila de eventos do PnP
do NT, em que o IoSetDeviceInterfaceState só enfileira a mudança), e o
PnpBootDeviceWait desse modo (`io/boot_partition.rs`) abre o volume cuja
primeira extensão (IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS) é a partição de
boot, o que monta o ntfs.sys nele, marca DO_SYSTEM_BOOT_PARTITION o
dispositivo da abertura, o do file system montado e as bases deles (o
mountmgr.sys lê a base do dispositivo da abertura dele), entrega as
chegadas ao mountmgr.sys e pede a letra pelo
IOCTL_MOUNTMGR_BOOT_DL_ASSIGNMENT: o C: e o NtSystemRoot. Como no 19041, o
ZwLoadDriver dos drivers que a árvore carrega não roda as rotinas de
reinicialização da fila antes do IoInitSystem
(`io/lifecycle.rs::run_reinitialization_routines_after_load`, o
IopInitSystemCompletedEnoughForReInitRoutines): a
MountMgrDriverReinitialization, que liga a atribuição automática de
letras, fica para o fim dos drivers, e o volume de boot não recebe a
primeira letra livre antes do BOOT_DL. O ExReinitializeResourceLite segue
o 19041 (devolve sempre STATUS_SUCCESS e esquece a posse): o ntfs.sys
reinicializa o ERESOURCE de um FCB que ele libera ainda adquirido e o
reaproveita no FCB seguinte, e sem isso a primeira abertura no volume do
sistema esperava para sempre. O `\SystemRoot` ainda leva ao
volume do kernel, e o driver ATA interno continua servindo o NTFS do
kernel depois do atapi.sys (o que o S1 tira).

Os riscos conhecidos: o tempo de boot (cada leitura atravessa seis ou sete
drivers e uma interrupção), o Cc e o ntfs.sys sob a carga da cadeia
(ordem dos recursos do ntfs.sys contra os callbacks de AcquireForLazyWrite
e AcquireForModWrite, o estrangulamento do CcCanIWrite, os checkpoints do
$LogFile de 2 MB) e a depuração do ntfs.sys sem os tipos no PDB público.

Com `--display=basic` (`drivers/video/display_stack.rs`) o adaptador VGA
recebe o BasicDisplay.sys real. O DriverEntry dele carrega o dxgkrnl.sys
real (ZwLoadDriver do DXGKrnl) e se registra nele (DxgkInitialize); o
AddDevice e o START_DEVICE vão ao dxgkrnl (DpiAddDevice, com o
DxgkDdiAddDevice do miniport, e DpiFdoHandleStartDevice). O dxgkrnl deixa o
início do adaptador (DpiFdoStartAdapterThread, com o DxgkDdiStartDevice)
para a criação da primeira sessão, que o win32k.sys anuncia
(watchdog!SMgrNotifySessionChange no NtUserInitialize). Com a mesma opção a
fase 1 grava, antes de qualquer enumeração da raiz, a instância
`ROOT\BasicRender\0000` só com o HardwareID (a que o IoReportRootDevice do
DriverEntry do BasicRender.sys cria no primeiro boot de uma instalação); a
raiz a enumera e o PnP a instala pelo basicrender.inf com o BasicRender.sys
real do repositório de drivers, que o dxgkrnl trata como o adaptador WARP
(`\Driver\BasicRender`): o adaptador de renderização em que o cdd.dll cria o
dispositivo da sessão e que leva o dxgkrnl a carregar o dxgmms2.sys
(`BASICRENDER_OK` depois da árvore, `RENDER_ADAPTER_STARTED` quando o
adaptador inicia).

Com `--usb` (a opção de carga `USB`, `drivers/bus/usb_stack.rs`; no xtask, também
os dispositivos do QEMU) a máquina tem a controladora xHCI
do QEMU (qemu-xhci, PCI\VEN_1B36&DEV_000D) com um teclado e um tablet USB, e
a árvore sobe a pilha USB 3 e HID da caixa pelas linhas de modelo de
`pnp/install_usb.rs`: o usbxhci.sys (KMDF, com a extensão de classe
ucx01000.sys, que a WdfLdr carrega pela chave Control\Wdf\Kmdf\Ucx) na
controladora, o usbhub3.sys no hub raiz (USB\ROOT_HUB30), o hidusb.sys com o
hidclass.sys nos dispositivos HID (USB\Class_03) e o kbdhid.sys e o
mouhid.sys nas coleções de teclado e de mouse, com os filtros de classe
kbdclass e mouclass. Como as ações do PnP manager do NT, que rodam numa
worker thread, com a pilha USB a árvore construída uma vez no fim da fase 1
(`device_tree::build`) é processada numa thread de sistema
(`tree::process_on_system_thread`) e o contexto de boot espera por ela
girando as interrupções, os DPCs e o escalonador, que entra nas worker
threads dos work items: nenhum work item fica empilhado sobre um START que
segura as travas da máquina de estados PnP do KMDF. Os demais boots seguem no
contexto de boot: as leituras do Code Integrity (`--start-driver`) pelo
driver ATA interno ainda param numa thread de sistema. A controladora entra nessa
árvore; a pilha USB só espera a enumeração das portas e confere os marcos.
Com a raiz ACPI (o padrão, a do teste `usb`) a controladora é enumerada
pelo pci.sys real e instalada pelo usbxhci.inf, e as mensagens dela são
arbitradas pelo árbitro de IRQ do acpi.sys, como no NT (veja as
interrupções por mensagem abaixo); com `--pnp-root=internal` o barramento
PCI interno pede as mensagens e o PnP manager as atribui.
O KMDF do usbxhci.sys troca a lista no IRP_MN_FILTER_RESOURCE_REQUIREMENTS
(libera a recebida e devolve outra em Information), que por isso começa com
STATUS_SUCCESS, como no IopFilterResourceRequirementsCall. As portas são
enumeradas depois do START: o IoInvalidateDeviceRelations do hub enfileira a
reenumeração e o PnpDeviceActionWorker (`tree.rs`), hospedado numa thread de
sistema (antes do processo System, num work item da fila atrasada); a pilha
USB também drena a fila enquanto espera os marcos (`tree::process_pending`),
um processamento por vez pela mesma marca do worker. O teclado USB passa a ser o da
máquina: o QEMU entrega a ele as teclas e o serviço de teclado lê do
kbdclass sobre o kbdhid. A hive leva o `Services\kbdclass\Parameters` de
uma instalação (ConnectMultiplePorts = 0, KeyboardDeviceBaseName =
KeyboardClass): cada porta de teclado, o i8042prt e o kbdhid de cada teclado
HID, recebe o próprio FDO nomeado `\Device\KeyboardClassN`; sem a chave o
kbdclass fica no modo "grand master", com um só dispositivo nomeado e os
FDOs das portas sem nome. O serviço de teclado abre o `\Device\KeyboardClassN`
com FILE_READ_DATA (o kbdhid só começa a ler os relatórios da coleção numa
abertura com acesso de leitura); a abertura desce pelo
kbdhid até a coleção do hidclass, que pede a sessão de quem abre
(IoGetRequestorSessionId): como no IopParseDevice, todo IRP_MJ_CREATE de uma
abertura por nome leva a thread que abre em Irp->Tail.Overlay.Thread
(`io_manager::open_file_object`; teste `io_create_thread` na fase 6).

Com `--net` (a opção de carga `NET`, `drivers/net/net_stack.rs`; no xtask,
também `-netdev user -device e1000`, a placa Intel PRO/1000 MT, PCI
8086:100E, com a rede de modo usuário do QEMU) a pilha de rede do Windows
sobe sobre a placa. Antes da árvore do boot sobem o ndis.sys, o tcpip.sys e
o afd.sys, drivers de boot e de sistema no Windows (grupos NDIS e PNP_TDI);
o tcpip.sys registra os protocolos TCPIP e TCPIP6 no NDIS
(NdisRegisterProtocolDriver pelo FlAttachClient do NMR). Na árvore, o
pci.sys relata a placa e a linha do nete1g3e.inf (`pnp/install_net.rs`,
seção E100E, a genérica PCI\VEN_8086&DEV_100E que casa com o subsistema
1AF4:1100 do QEMU) a instala com o serviço E1G60 (o E1G6032E.sys, que no
Windows o `[e1000.CopyFiles]` copia para o System32\drivers; nesta máquina
ele só está no repositório de drivers, e o xtask o copia de lá, coberto
pelo catálogo 0110), o AddReg da seção e o que o instalador da classe Net
grava na chave do driver: as diretivas `*IfType`, `*MediaType`,
`*PhysicalMediaType`, `Characteristics` e `BusType`, o NetCfgInstanceId, o
NetLuidIndex, o ComponentId, o DeviceInstanceID e a `Linkage`. O ndis.sys
do Windows 10 lê o adaptador e as ligações do banco da configuração de rede
(`Control\NetworkSetup2`), que o serviço de configuração mantém e que aqui
vem da instalação (`cm/network_setup.rs`, na hive SYSTEM): o objeto da
interface em `Interfaces\{NetCfgInstanceId}\Properties` (cada propriedade é
a subchave `{a111f1xx-5923-47c0-9a68-d0bafb577901}\PPPP` com o valor padrão
do tipo 0xFFFF0000 | DEVPROP_TYPE: NetLuid, IfAlias, IfDescr, IfType, os
tipos de mídia e as Characteristics do INF), de onde o NDIS cria o bloco da
interface na partida (sem ele o AddDevice falha com 0xC00002F0); as
ligações em `Interfaces\{guid}\Kernel` (o ProtocolList, TCPIP e TCPIP6); e
os objetos dos protocolos (`Protocols\Lookup` com o GUID de cada nome e
`Protocols\{GUID}\Properties`). O NetLuidIndex 0x8000 fica na faixa que o
serviço de configuração reserva (0x7F00 a 0xC000, que o NDIS não confere no
bitmap). O AddDevice do miniport é o do NDIS (ndisPnPAddDevice: o FDO
`\Device\NDMP1` com o link `\Device\{NetCfgInstanceId}` e a interface
GUID_DEVINTERFACE_NET); no START o NDIS chama o MiniportInitializeEx, e o
E1G6032E.sys mapeia o BAR0 (NdisMMapIoSpace), registra as portas, a
interrupção de linha (NdisMRegisterInterruptEx, IRQ 11 pelo _PRT e pelo
árbitro do acpi.sys) e o DMA de dispersão (NdisMRegisterScatterGatherDma,
pelo adaptador de DMA da HAL), aloca os anéis de recepção e transmissão
(NdisMAllocateSharedMemory) e liga a recepção e a transmissão; o NDIS
responde o enlace conectado (OID_GEN_MEDIA_CONNECT_STATUS pelo
IOCTL_NDIS_QUERY_GLOBAL_STATS no `\Device\{NetCfgInstanceId}`) com o
endereço 52:54:00:12:34:56 (`NIC_STARTED`, `NIC_LINK_UP`). A configuração
IPv4 estática (10.0.2.15/24 com o gateway 10.0.2.2) também vem da
instalação, onde o netio.sys guarda o estado persistente do NSI e o
tcpip.sys a lê quando a interface sobe (`Control\Nsi\{ModuleId do
IPv4}\10` e `\16`: o nome do valor é a chave em hexadecimal e o dado os
parâmetros graváveis seguidos da máscara, no formato que o iphlpapi.dll
monta das estruturas públicas MIB_UNICASTIPADDRESS_ROW e
MIB_IPFORWARD_ROW2). O eco ICMP do teste (`drivers/net/echo.rs`) é um
cliente do Winsock Kernel (WskRegister e WskCaptureProviderNPI do NETIO.SYS,
o provedor é o afd.sys, um socket IPv4 bruto do ICMP). A ligação do TCP/IP
ao adaptador ainda não acontece: o NDIS só liga os protocolos de um
miniport cujo estado de ligação está limpo, e o bit 0x80000 que o
ndisMInitializeAdapter liga só sai na chegada da interface
GUID_DEVINTERFACE_NET ao callback do próprio NDIS
(ndisMiniportDeviceReadyNotification, registrado pelo
IoRegisterPlugPlayNotification); no NT essa chegada vai pela fila de
eventos do PnP e chega depois do START. O OpenNT ainda a entrega dentro do
IoSetDeviceInterfaceState, no meio do START e antes de o bit ser ligado.

O KMDF registra os dispositivos no power framework com o PO_FX_DEVICE_V2
(e o V3 do Directed Power Management): o PoFxRegisterDevice (`po/fx.rs`)
aceita as três versões com o layout de cada uma, e o KMDF guarda a tabela
de notificação do WDF que o WmiQueryTraceInformation (classe 15,
`etw/wmi.rs`) devolve, nula sem sessão de trace.

O KMDF (e o storport.sys, quando o miniport prefere o DMA v3) pede o
adaptador de DMA com a DEVICE_DESCRIPTION da versão 3; o adaptador é o de
`hal/dma.rs` com a tabela HalpDmaOperationsV3, uma só, em `hal/dma_v3.rs`:
as rotinas da versão 3 no caminho de bus master do NT sem IOMMU
(GetDmaAdapterInfo com ADAPTER_INFO_API_BYPASS e a largura do adaptador,
FlushAdapterBuffersEx, FlushDmaBuffer pelo alinhamento, GetDmaTransferInfo,
InitializeDmaTransferContext, Get/BuildScatterGatherListEx pelo Offset da
cadeia de MDLs, AllocateAdapterChannelEx, MapTransferEx, os domínios de DMA
como agrupamento e os vetores de buffers comuns).

**Interrupções por mensagem (MSI e MSI-X)**, com a divisão do NT:
- o barramento (`drivers/bus/pci_msi.rs`, o papel do pci.sys) acha as
  capacidades MSI e MSI-X e, quando o INF pediu (o `MSISupported` da chave
  `Interrupt Management\MessageSignaledInterruptProperties` do hardware,
  limitado pelo `MessageNumberLimit`), pede as mensagens nos requisitos:
  descritores de interrupção LATCHED|MESSAGE com Mínimo/Máximo até o
  CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN (um por mensagem no MSI-X, sem a
  linha; um para n mensagens no MSI, com uma mensagem e a linha como
  alternativas). Como a instalação reinicia o nó no NT, o PnP pede os
  requisitos de novo depois de instalar;
- sem árbitro de IRQ de driver (a raiz do barramento PCI interno), os
  árbitros da raiz (`pnp/message_interrupts.rs`) não arbitram as mensagens
  contra as linhas: o recurso bruto leva o token e o MessageCount, e a
  tradução pede à HAL um bloco de vetores (`hal/message_interrupts.rs`:
  0x50-0xCF, IRQL = vetor >> 4, destino físico no processador 0, endereço
  0xFEE00000 | APIC ID << 12 e o dado do HalpApicGenerateMessage) e grava
  os dados de conexão
  do PDO (INTERRUPT_CONNECTION_DATA_PKEY) com uma entrada
  InterruptTypeMessageRequest por mensagem, o endereço e o dado no
  IntRemapInfo.u.Msi;
- o START do barramento lê essas entradas, pede o endereço e o dado ao
  HalGetMessageRoutingInfo, programa a tabela MSI-X (ou o MSI), liga a
  capacidade e desliga o INTx;
- o IoConnectInterruptEx MESSAGE_BASED (`io/message_interrupt.rs`) monta a
  IO_INTERRUPT_MESSAGE_INFO como o IopConnectMessageBasedInterrupt (o
  UnifiedIrql, um objeto por mensagem com a MessageServiceRoutine chamada
  com o MessageID, e a linha pela FallBackServiceRoutine quando não há
  mensagens); o KMDF conecta cada mensagem com FULLY_SPECIFIED pelo vetor
  traduzido. Os vetores de mensagem são de borda e do APIC local (os
  trampolins mandam o EOI dos vetores 0x30 em diante a ele; o 8259 só
  entrega 0x20-0x2F). O IoGetAffinityInterrupt de um objeto (linha ou
  mensagem) dá o grupo 0 e o processador que recebe as interrupções dele,
  guardado no objeto de `ke/interrupt_object.rs` (o layout desse objeto é
  do OpenNT, não o do KINTERRUPT).
- com a raiz ACPI, o pci.sys real pede as mensagens e o árbitro de IRQ do
  acpi.sys as arbitra, como no NT: o ProcessorAddInstance guarda por
  processador a INTERRUPT_TARGET_INFORMATION do
  HalGetInterruptTargetInformation, e o IrqArbpFindSuitableRangeMsi só dá
  vetores de mensagem (do conjunto da raiz, pelo ProcessorFindIdtEntries)
  quando a flag de MSI (+8, bit 0) dela está ligada. A HAL
  (`hal/interrupt_targets.rs`) liga a flag pelo HalpInterruptIsMsiSupported:
  o APIC local gera mensagens, a regra DisableMSI do Errata Manager
  responde e não é TRUE e o processador é Intel, AMD ou um Centaur recente;
  a decisão fica guardada. O bruto da mensagem leva o token no Vector e o
  traduzido o vetor e o IRQL que o tradutor do acpi.sys deu; o PnP manager
  não toca nessas mensagens (só traduz as que ninguém traduziu). O acpi.sys
  grava os dados de conexão do PDO (InterruptTypeMessageRequest) e pede o
  endereço e o dado ao HalAddInterruptRemapping da HalPrivateDispatchTable
  (o IrtRemapNewMsiAssignments): sem IOMMU, o HaliAddInterruptRemapping
  (`hal/message_interrupts.rs`) faz o HalpPopulateMsiMessages, com o
  endereço e o dado do HalpApicGenerateMessage físico (0xFEE00000 | APIC
  ID << 12; vetor | 0x100, entrega de menor prioridade, | 0x4000, Level)
  no IntRemapInfo.u.Msi; o mesmo dado vale para as mensagens do barramento
  interno. O pci.sys lê essas entradas (PciGetInterruptConnectionData),
  pede o endereço e o dado ao HalGetMessageRoutingInfo e programa a tabela
  MSI-X.

A raiz da árvore (`drivers/bus/acpi_stack.rs`; `--pnp-root=internal` volta
ao barramento PCI interno) é a de um PC ACPI do Windows:

- **A HAL** (`hal/pnp.rs`, o HalpDispatchPnp) relata o computador
  `ROOT\ACPI_HAL\0000` (HardwareID `acpiapic`; o kernel é o driver dele) e,
  como filho, o AcpiRootPdo `ACPI_HAL\PNP0C08\0` (FILE_DEVICE_BUS_EXTENDER,
  UniqueID, os ids `ACPI_HAL\PNP0C08`/`*PNP0C08`). Os requisitos e a
  configuração de boot dele são os vetores da IDT de dispositivos
  (0x37-0xCC, um descritor exclusivo por vetor), que o acpi.sys guarda como
  os vetores da raiz. O PnP o instala pelo acpi.inf (`*pnp0c08`, serviço
  ACPI com Tag 2 e Group Core; `install.rs`, `ACPI_ROOT_DRIVERS`).
- **A tabela de energia da HAL** (`hal/acpi_pm.rs`): o HalInitPowerManagement
  do HalDispatchTable (slot +0x68) troca a tabela do acpi.sys pela
  HalAcpiDispatchTable ('HAL ', versão 4, 21 rotinas, na ordem da do
  ntoskrnl 19041): as tabelas do firmware pelo cache da HAL (cópias da
  RSDT, DSDT e das demais; a lista do GetAllTables sem DSDT/RSDT/XSDT/FACS;
  a FACS mapeada), os registradores de PM da FADT (PM1a/b, PM_TMR, PM2,
  GPE0/1 e RESET_REG, com as regras do HalpAcpiSetupPmRegisterLegacy), a
  configuração PCI, o modelo de interrupção APIC para o `_PIC` e a versão
  dos IOAPICs da MADT (`hal/interrupt_lines.rs`). O HalQuerySystemInformation
  (slot +0x08, `hal/system_information.rs`) responde a BadIOAddrList (com o
  tratador de 0xCF8), as informações de depurador, de controladores
  secundários e o limite de MSI. As rotinas vão por ponteiro pelos stubs de
  `routine_stubs.rs` (agora 128).
- **O que o carregador do NT deixa e o acpi.sys lê**: o adaptador
  `HARDWARE\DESCRIPTION\System\MultifunctionAdapter\1` "ACPI BIOS" com a
  RSDT e o mapa E820 (`cm/hw_description.rs`) e, na hive SYSTEM,
  `Control\Arbiters` da instalação (`cm/arbiters.rs`), de onde os árbitros
  do acpi.sys tiram a ordem de alocação e as faixas reservadas.
- **A SCI**: o acpi.sys grava os dados de conexão da interrupção no
  AcpiRootPdo (INTERRUPT_CONNECTION_DATA_PKEY) e chama o IoConnectInterruptEx
  LINE_BASED; como o IopConnectLineBasedInterrupt, a conexão usa esses dados
  (a GSIV 9 da FADT e o vetor que ele atribuiu).
- **A entrega das interrupções de linha** (`hal/interrupt_lines.rs`): o
  árbitro de IRQ do acpi.sys escolhe o vetor do IDT de cada GSI no conjunto
  da raiz (GSIs no mesmo IRQL podem dividir um vetor) e o tradutor dele o
  entrega na lista traduzida. A HAL do NT programaria o IOAPIC; a do OpenNT
  entrega as linhas pelo 8259 no vetor fixo `0x20 + linha`, registra cada
  linha com o vetor atribuído a ela (pela tradução no PnP ou pelos dados de
  conexão) e o KINTERRUPT conectado num vetor atribuído fica na cadeia
  dele, que as linhas desse vetor despacham.
- **Destinos de interrupção** (`hal/interrupt_targets.rs`): HalGetProcessorIdByNtNumber,
  HalGetInterruptTargetInformation (modo físico, com a flag de MSI do
  HalpInterruptIsMsiSupported), HalGetMessageRoutingInfo,
  HalConvertDeviceIdtToIrql e HalGetMemoryCachingRequirements, que o acpi.sys
  importa pela hal.dll.

O acpi.sys carrega a DSDT no interpretador AML dele e as BusRelations da
raiz são os dispositivos do namespace do QEMU: `ACPI\PNP0A03\0` (o PCI0,
com UID 0), `ACPI\PNP0103` (HPET), `ACPI\ACPI0010` (o contêiner dos
processadores) e `ACPI\FixedButton`; o prefixo de instância que o PnP
deriva do AcpiRootPdo (`2&daba3ff&0`) é o mesmo da instalação desta
máquina. O nó PNP0A03 recebe o pci.sys pelo pci.inf (PCI_ROOT); a pshed.dll
que ele importa carrega como DLL de modo kernel do volume. O DriverEntry
do pci.sys consulta o Errata Manager (as regras de PCI da FADT, FALSE no
QEMU) e registra o provedor do PCIDevice; o AddDevice abre o
`Control\PnP\Pci\CardList` (`cm/pnp_control.rs`); o START recebe as janelas
do `_CRS` do PCI0 e o pci.sys lê a configuração das funções pela interface
de barramento PCI que o acpi.sys dá ao PDO, avalia as regras de PCIDevice
com os próprios callbacks e relata as funções com os ids dele
(`PCI_ROOT_OK`). A ponte PCI-ISA recebe o msisadrv.sys e o filtro do
acpi.sys sobre o PDO dela relata os dispositivos ISA do namespace
(PNP0303, PNP0F13, PNP0700, PNP0400, PNP0501, PNP0B00); o teclado e o
mouse PS/2 são instalados pelas linhas do keyboard.inf e do msmouse.inf
(`io/pnp/install.rs`) com o i8042prt.sys e os filtros de classe, e a
pilha do teclado do boot é a desse nó (`drivers/input/keyboard_stack.rs`).
As chaves das classes Keyboard e Mouse ficam no conjunto de controle
(`CurrentControlSet\Control\Class\{4D36E96B-...}` e `{4D36E96F-...}`,
com os valores da instalação do Windows: Class, ClassDesc, UpperFilters =
kbdclass/mouclass, IconPath, NoInstallClass e, na Mouse, o Default
Service), onde o PnP lê os UpperFilters. No boot do shell o kernel abre a
porta do teclado e o serviço de teclado mantém um READ no
`\Device\KeyboardClass0`; no boot do processo inicial real
(`--initial-process=smss`) nenhum dos dois existe: o RIT do win32k de
cada sessão acha o teclado e o mouse pelas interfaces de dispositivo que o
kbdclass e o mouclass registram, abre cada uma (o CREATE no kbdclass
desce ao i8042prt e habilita a porta, no KbdEnableDisablePort) e lê com o
próprio READ assíncrono. A primeira leitura do teclado concluída com dados
para um leitor de modo kernel com rotina de APC (o ZwReadFile do RIT, com o
rimInputApc) sai na serial com o `KEYBOARD_INPUT_OK` (`io/file/request.rs`):
a tecla chegou ao win32k.
Os recursos de todos esses nós passam pelos árbitros e tradutores dos
drivers de barramento (`io/pnp/arbiter.rs`): o teclado recebe as portas
0x60/0x64 do árbitro do pci.sys e a IRQ 1 do árbitro do acpi.sys, com o
vetor que o tradutor dele dá. Os dispositivos sem driver na caixa ficam
sem instalação (CM_PROB_FAILED_INSTALL): a placa de rede e1000 sem `--net`
(com a opção ela recebe o E1G6032E.sys, veja a pilha de rede abaixo), a
controladora de disquete (fdc.inf), as portas serial e paralela (msports.inf; o serial.sys
tomaria a COM1, que é a saída do log do kernel), o fw_cfg do QEMU e o
processador (cpu.inf). O barramento PCI interno do kernel fica fora dessa
árvore; as funções dos drivers internos são reconhecidas pelos ids de
classe do pci.sys (`device_tree.rs`).

Com `--tpm` (a opção de carga `TPM`, `drivers/security/tpm_stack.rs`; no
xtask, também o dispositivo do QEMU) a máquina tem um TPM 2.0 com interface
CRB. O QEMU expõe o `tpm-crb`: o dispositivo `TPM` no `\_SB` da DSDT, com
`_HID` MSFT0101 e a janela MMIO em 0xFED40000, e a tabela ACPI TPM2 com
start method 7 e a área de controle em 0xFED40040. O backend do TPM é o
`mssim` do QEMU do OpenNT (`tools/qemu/tpm-mssim.patch`), que fala o
protocolo TCP do simulador de TPM 2.0 de referência: uma porta de comandos e
a seguinte, de plataforma (energia, NV, cancelamento). O xtask sobe o
simulador (`tpm_server.exe`, ao lado do QEMU, ou a variável
`TPM_SIMULATOR`) em duas portas livres, com o estado NV e o log na pasta
temporária da execução (`qemu-tmp`), e o mata antes de apagar a pasta. O
reset do dispositivo no QEMU desliga e religa o TPM pelo canal de
plataforma, como um reset da placa. O SeaBIOS manda o TPM2_Startup e
estende os PCRs dele antes do boot. A máquina com `--tpm` roda no TCG
(`qemu::machine_accelerator`, e `acelerador = "tcg"` no teste): o WHPX do
QEMU não mapeia as regiões de memória do tpm-crb (o buffer de comando de
0xF80 bytes e o PPI de 0x400), e o QEMU para no realize do dispositivo com
"WHPX: failed to unmap GPA range".

O acpi.sys relata o `ACPI\MSFT0101` sob a raiz ACPI e o instalador o casa
com o tpm.inf (`[Tpm2BaseInstall]`: serviço TPM sob demanda, grupo Boot Bus
Extender, BootFlags 0x20, classe SecurityDevices e HardwareType 20 no
Device Parameters). O tpm.sys real é um driver KMDF. O DriverEntry escolhe
o transporte pela tabela TPM2 (TpmTransportType::Determine): ele a lê pelo
HalGetCachedAcpiTable da HalDispatchTable (slot +0xA8), que no ntoskrnl
19041 é o HalAcpiGetTableDispatch gravado pelo HalpSetupAcpiPhase0 numa
máquina ACPI (o slot do OpenNT aponta para a mesma rotina da
HalAcpiDispatchTable). A revisão 3 ou 4 da tabela e o start method 7 dão o
transporte CRB. O kernel não manda comandos ao TPM no boot: no ntoskrnl
19041 o único uso é o BapdRegisterSiData, que copia para
`Control\IntegrityServices` os dados de integridade que o winload deixa
(TPMActivePCRBanks, TPMActiveLogFormat, TPMDigestAlgID). As medições do boot
são do carregador com o firmware; sem o winload o OpenNT não as tem e não
as inventa.

A ida e volta de comandos usa o caminho dos componentes de kernel do
Windows: o tbs.sys, o export driver da API de TPM de kernel, carregado como
biblioteca. O Tbsi_Context_Create (TBS_CONTEXT_PARAMS2, versão 2 com
includeTpm20) abre o `\??\TPM`, que o AddDevice do tpm.sys liga ao nome do
PDO (IoGetDeviceProperty com DevicePropertyPhysicalDeviceObjectName). O
KMDF devolve STATUS_PENDING de todo IRP_MJ_CREATE que entrega ao
EvtDeviceFileCreate, mesmo concluído dentro do despacho; como o
IopParseDevice, a abertura por nome do I/O Manager espera a conclusão do IRP
e fica com o status final (`io_manager::open_device_file`), e um create
recusado devolve ao ZwCreateFile o status do driver. O Tbsip_Submit_Command
manda cada comando por IOCTL ao tpm.sys, que o leva ao TPM pelo CRB. O
tpm.sys bloqueia o TPM2_Startup de todo cliente do TBS: o código 0x144 não
está em nenhuma das três listas de comandos permitidos por tipo de usuário
do Tpm20Scheduler::IsCommandBlocked, e a resposta é o cabeçalho com
TPM_E_COMMAND_BLOCKED (0x80280400). O TPM2_GetRandom e o TPM2_GetCapability
estão nas três listas e vão ao TPM. Os marcadores: `TPM_DEVICE_FOUND` (o
MSFT0101 relatado e a tabela TPM2 no firmware), `TPM_STARTED` (o nó
iniciado com o FDO do \Driver\TPM) e `TPM_COMMAND_OK` (o Startup bloqueado
pelo tpm.sys, 16 bytes do TPM2_GetRandom e o TPM_PT_MANUFACTURER do
TPM2_GetCapability). O TPM2_PCR_Read do PCR 0 (SHA-256) vai para o log, com
o valor das medições do firmware.

O QEMU do OpenNT com o TPM: as fontes do QEMU 11.1.0 com o
`tools/qemu/tpm-mssim.patch` (o backend `tpm_mssim.c`, o tipo `mssim` no
`qapi/tpm.json` e o TPM liberado no Windows, só com esse backend, porque o
`emulator` passa o socket de dados por SCM_RIGHTS), configurado com
`--enable-tpm`. O simulador compila com o MSYS2 UCRT64 (gcc e OpenSSL 3) pelo
makefile de Windows dele (`-DTPM_WINDOWS`, `-lcrypto -lws2_32`); o
`tpm_server.exe` precisa do `libcrypto-3-x64.dll` e do `libwinpthread-1.dll`
na mesma pasta.

A RAM do convidado no QEMU do OpenNT: com o `tools/qemu/lazy-ram.patch`, o
QEMU no Windows só reserva (VirtualAlloc com MEM_RESERVE) os blocos de RAM
de 512 MB ou mais e compromete pedaços de 64 KB no primeiro acesso. Sem o
patch, o QEMU compromete a RAM toda ao subir: um convidado de 8 GB cobra
8,2 GB do commit do host desde o primeiro segundo, embora o boot até o
LogonUI toque uns 500 MB. No mesmo boot do teste `logonui` com 8 GB, os
bytes privados do QEMU chegam a 8508 MB sem o patch e a 777 MB com ele, e
o LogonUI sobe no mesmo tempo (31,7 s e 31,8 s). No `test-all --jobs 2`
(66 testes passando, convidados de 8 GB), os dois QEMUs somaram no máximo
3,6 GB de bytes privados (1,9 GB em média), contra 17,0 GB sem o patch, e o
limite de commit do host não mudou: o arquivo de paginação não cresceu.
Três caminhos comprometem a RAM. O WHvMapGpaRange aceita uma faixa só reservada, e o acesso do
convidado a uma página sem commit volta do WHvRunVirtualProcessor como
WHvRunVpExitReasonMemoryAccess, com o GPA mapeado (GpaUnmapped = 0) e a
instrução por executar: o acelerador compromete o pedaço e roda a
instrução de novo (`whpx_commit_guest_ram`). O acesso do próprio QEMU cai
num tratador de exceção vetorizado, que compromete o pedaço e retoma o
acesso. O kernel do host não compromete por ninguém (um ReadFile num
buffer só reservado volta ERROR_NOACCESS), então o `address_space_map`, de
onde saem os buffers de DMA dos discos, compromete a faixa antes de
devolvê-la. O commit não volta: o de um QEMU cresce com a RAM que o
convidado já tocou e pode chegar ao tamanho dela. Sem commit livre, o
pedido espera até 10 s o arquivo de paginação crescer e depois o QEMU para
com `cannot commit guest RAM`.

As instruções de string de I/O (o `rep outsb` da serial, `hal/serial.rs`)
no QEMU do OpenNT: com o `tools/qemu/whpx-string-io.patch`. No QEMU 11.1 o
WHPX emula um OUTS/INS com o emulador x86 do próprio QEMU, que decodifica
os bytes que a saída de I/O traz. O Hyper-V às vezes entrega a saída sem
eles (InstructionByteCount 0, o buffer zerado), e o QEMU original
decodificava o comprimento da instrução (2) sobre esse buffer: rodava
`00 00`, um `add [rax], al`, no lugar do `rep outsb`. Com o RAX do `rdtsc`
de `send`, um endereço da metade de usuário, a leitura falhava no passeio
de tabelas do emulador e o convidado recebia um #PF com erro 0x8 e CR2 0 no
`rep outsb`, com RCX e RSI intactos (o erro 0x8 vinha de outro defeito: o
emulador testava o resultado da tradução como bits, e PAGE_NOT_MAPPED ganhava
o bit RSVD; o CR2 0, de a leitura não passar o endereço ao acelerador). Com
o RAX mapeado, o `add` alteraria aquele byte e o lote da serial sumiria. A
saída sem bytes aparece quando o host tira a RAM do convidado do working
set do QEMU. Com o working set do QEMU esvaziado a cada 20 ms
(EmptyWorkingSet) durante boots do `ata-falha`, chegaram sem bytes quatro
saídas de string em nove boots, duas em três com o `lazy-ram.patch` e duas
em seis sem ele. O QEMU sem a correção parou o convidado com esse #PF no
quinto boot (o binário de antes do `lazy-ram.patch`) e no primeiro (o com
ele); com a correção, 12 boots do `ata-falha` e a `suite-smp4` passaram
assim. As duas falhas vistas nas suítes completas vieram com 10 a 16 QEMUs
ao mesmo tempo no host. O patch passa ao decodificador só os bytes que o
Hyper-V trouxe (o resto ele lê da memória
do convidado, como já fazia nas saídas de acesso à memória), dá ao #PF do
emulador o código de erro certo e o CR2 do endereço lido, e para o OUTS no
elemento cuja leitura falhou, sem escrever na porta.

O build: as fontes do QEMU 11.1.0 com os três patches de `tools/qemu`
(`tpm-mssim`, `lazy-ram` e `whpx-string-io`, nessa ordem),
`configure --target-list=x86_64-softmmu --enable-whpx --enable-tpm
--enable-sdl --disable-werror --disable-docs` e `ninja
qemu-system-x86_64.exe` no MSYS2 UCRT64, com TMP e TEMP numa pasta que
exista.

### 3.6 A interface x86 BIOS

Os drivers de vídeo do Windows chamam o BIOS de vídeo da máquina (as
funções VBE do INT 10h) pela interface x86 BIOS da HAL: x86BiosCall,
x86BiosAllocateBuffer, x86BiosFreeBuffer, x86BiosReadMemory e
x86BiosWriteMemory, exports do ntoskrnl que a hal.dll encaminha (o
BasicDisplay.sys os importa da HAL.dll; o dxgkrnl.sys, o x86BiosCall). No
x64 não há modo virtual 8086: o Windows executa o código de 16 bits do BIOS
num emulador de x86 dentro do kernel. O OpenNT faz o mesmo em `hal/x86bios/`:

- `emulator.rs` e `operations.rs`: o processador do 386 em modo real
  (operandos e endereços de 16 e 32 bits, SIB, prefixos de segmento,
  REP/REPNE), com o contrato do emulador do ntoskrnl 19041: limite de 64 KB
  por segmento (o operando ou a busca de código que passa de FFFFh para a
  emulação), pilha pelo ESP inteiro, o mapa de opcodes dele (sem x87 nem
  instruções de sistema; SMSW lê 2Dh, RDTSC lê o contador de desempenho),
  INT n pela IVT sem mexer em IF/TF, INT 42h ignorada, INT 1Ah pelo PCI BIOS
  emulado, e o fim da chamada quando um IRET/RET/RETF chega ao quadro falso
  FFFF:FFFF. Os códigos de parada são os do NT (1 sucesso, 2/3 divisão, 5
  HLT, 9 porta, 0xC opcode ilegal, 0xE limite, 0xF/0x10 pilha...). O núcleo é
  puro (um `Bus` dá memória e portas) e foi conferido instrução a instrução
  contra um processador de referência em todas as chamadas VBE que o
  BasicDisplay faz ao BIOS de vídeo do QEMU (4F00h, 4F01h de cada modo,
  4F02h, 4F03h, 4F09h, 4F10h, 4F15h e as trocas de modo 03h, 12h e 101h).
- `mod.rs`: a inicialização (o HalInitializeBios, logo depois das tabelas
  da HAL na fase 1) e o mapa de 1 MB que o BIOS vê: a IVT e a BDA copiadas
  da memória física para um buffer privado (0-800h), memória de rascunho
  (lê zero), o buffer de transferência de 8 KB em 2000:0000 (também visto em
  3000h), a janela VGA física (A0000h-BFFFFh, mapeada pelo MmMapIoSpaceEx) e
  o resto do primeiro megabyte físico (EBDA e ROMs) por uma visão página a
  página em que a RAM do sistema e a janela VGA viram a página F0000h da ROM
  — o BIOS nunca enxerga a memória do sistema. Uma chamada empilha o quadro
  falso em 0000:0800, carrega o vetor da IVT copiada e os registradores do
  X86_BIOS_REGISTERS (`inc/types/extra_hal.rs`) e devolve TRUE só quando o
  BIOS volta ao quadro. O estado é um só, atrás de um lock: uma chamada por
  vez.
- `io_space.rs`: as portas vão ao hardware, menos o mecanismo de
  configuração PCI (CF8h/CFCh num latch próprio, com as leituras e escritas
  pelas rotinas KdGet/SetPciDataByOffset da HalPrivateDispatchTable) e o
  índice da CMOS (70h num latch, 71h sob o lock da CMOS de `hal/rtc.rs`); o
  INT 1Ah B1xxh é o PCI BIOS emulado sobre as mesmas rotinas.

O HalQuerySystemInformation da HalDispatchTable (`hal/system_information.rs`)
responde a classe HalDisplayBiosInformation com HalDisplayEmulatedBios, que
é o que o BasicDisplay consulta antes de usar o BIOS (sem ela, ele nem tenta
o VBE). O autoteste `ntos/test/x86_bios.rs` chama os exports pelo nome, roda
código de teste por um vetor livre da IVT copiada e conversa com o BIOS de
vídeo real: 4F00h ('VESA', VBE 3.0, a memória e a lista de modos), 4F01h (o
framebuffer linear no BAR0 do adaptador), 4F02h (os registradores de modo
do adaptador e da VGA confirmam o modo), 4F03h e a volta ao modo texto com o INT 10h
AX=0003h, com a posse do vídeo tirada do console (Inbv) durante as trocas.

## 4. Dependências

- Os componentes do executive se chamam entre si, como no NT (`ke` ↔ `ps`,
  `ob` ↔ `se`, `mm` → `cm`...).
- Nada em `ntos/` chama `shell` ou `apps`. Quando o executive precisa de algo
  de cima, a camada de cima se registra: o NTFS registra o volume de paginação
  (`mm::paging_volume::register`), o Mm instala o tradutor de endereços da
  memória de convidado. O registro acontece em `ntos/init`, na ordem do boot.
- **Hosts de extensão** (`ex/extension_host.rs`): como no NT, um
  componente que delega parte do trabalho a um driver registra um host
  (ExRegisterHost: id, versão, mínimo de funções) e o driver liga a tabela
  dele com ExRegisterExtension; o componente a usa entre
  ExGetExtensionTable/ExReleaseExtensionTable, sob o rundown do host. Os
  hosts registrados na fase 1 são o PCW (id 1, o pcw.sys; `ex/pcw.rs`
  despacha os cinco Pcw* para ele: PcwRegister, PcwUnregister,
  PcwCreateInstance, PcwCloseInstance e PcwAddInstance, as rotinas 0 a 4 da
  tabela, como no ntoskrnl 19041; sem a extensão, o status do
  ExpPcwDisabledStatus pelo Start do serviço pcw; com a extensão, a
  notificação ExpPcwHostCallback registra no pcw.sys os conjuntos de
  contadores do kernel, Processor Information, em
  `ex/processor_counter_set.rs`, e FileSystem Disk Activity, em
  `fsrtl/volume_support.rs`, com as rotinas de callback como rotinas por
  ponteiro de `hal/amd64/routine_stubs.rs`), a autorização (id 2, o ksecdd.sys) e o BCrypt
  (id 3, o cng.sys) do Se (`se/extension_hosts.rs`) e o controle de taxa de
  rede (id 4, o tcpip.sys) do Ps (`ps/net_rate_control.rs`).
- **Consultas de token** (`se/token/query.rs`): o NtQueryInformationToken
  e o ZwQueryInformationToken serializam cada classe do registro do token,
  com os ponteiros internos relativos ao buffer do chamador; o ReturnLength
  recebe o tamanho exigido antes da comparação com o Length, e um buffer
  curto devolve STATUS_BUFFER_TOO_SMALL sem nenhum byte gravado nele (o
  serviço de usuário, em `ps/user/tokens.rs`, só resolve o handle e sonda).
  A TokenAccessInformation (classe 22) segue o SepCopyTokenAccessInformation:
  o TOKEN_ACCESS_INFORMATION, os três SID_AND_ATTRIBUTES_HASH (com o hash do
  RtlSidHashInitialize), o PackageSid, os atributos de segurança no formato
  interno do token (o AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION e os
  registros de `inc/types/extra_obpsse.rs`, montados e lidos por
  `se/security_attributes.rs`) e o TOKEN_PRIVILEGES na ordem do LUID. O
  SeTokenFromAccessInformation e o SeQuerySecurityAttributesTokenAccessInformation
  consomem esse bloco. O SeQueryInformationToken grava a TokenSessionId e a
  TokenIsAppContainer direto no ULONG de saída, sem alocar. As classes
  TokenHasRestrictions (21, um BOOLEAN de um byte: IS_FILTERED ou
  IS_RESTRICTED), TokenVirtualizationAllowed (23), TokenVirtualizationEnabled
  (24), TokenUIAccess (26), TokenIsRestricted (40: IS_RESTRICTED ou
  WRITE_RESTRICTED) e TokenPrivateNameSpace (42) saem do TokenFlags do token,
  como no NtQueryInformationToken do 19041: o token filtrado do dwm.exe
  responde TRUE na 21.
- **Controle de acesso** (`se/access_evaluation.rs`): uma avaliação só, a do
  SeAccessCheckWithHint/SepAccessCheck do ntoskrnl 19041, sobre os
  componentes de um descritor (`OwnedDescriptor`) e a identidade do token
  efetivo (`Subject`: usuário, grupos, SIDs restritos, privilégios
  habilitados, SID de integridade, MandatoryPolicy, pacote e capacidades).
  Na ordem do NT: integridade obrigatória
  (SepMandatoryIntegrityCheck: o rótulo é a primeira ACE de rótulo da SACL,
  Medium com NO_WRITE_UP quando não há; quem não domina só tem GenericRead,
  GenericExecute, READ_CONTROL e SYNCHRONIZE, menos NO_READ_UP/NO_EXECUTE_UP,
  mais WRITE_OWNER com SeRelabelPrivilege; o MAXIMUM_ALLOWED é cortado pela
  mesma máscara); os direitos implícitos do dono (READ_CONTROL e WRITE_DAC,
  a menos que a DACL tenha OWNER RIGHTS); ACCESS_SYSTEM_SECURITY só com
  SeSecurityPrivilege; WRITE_OWNER pedido por SeTakeOwnershipPrivilege ou
  SeRelabelPrivilege (não no MAXIMUM_ALLOWED); DACL nula concede tudo, vazia
  nega; as passagens SepNormalAccessCheck/SepMaximumAccessCheck com as
  máscaras das ACEs como estão (deny-only só nas negadas), a segunda passagem
  de um token restrito (só escrita num WRITE_RESTRICTED) e a de pacote de um
  token LowBox. Uma ACE ACCESS_ALLOWED_CALLBACK (tipo 9) com dados depois do
  SID é condicional: a expressão `artx` (MS-DTYP 2.4.4.17,
  `se/conditional_ace.rs`) é avaliada como no AuthzBasepEvaluateAceCondition,
  com a lógica de três valores, sobre os atributos locais do token
  (`WIN://...` também os do sistema, como o `WIN://ISMULTISESSIONSKU` do
  SharedDataFlags), os atributos de recurso da SACL do descritor e os
  grupos (Member_of e afins; os de dispositivo são falsos), e a ACE só vale
  quando o resultado é TRUE; a negada condicional (tipo 0xA) não é
  avaliada, como no 19041. Os exports (SeAccessCheck, SeAccessCheckFromState(Ex),
  SeAccessCheckEx, `se/access_check.rs`), o `object_access::check_token` de
  todas as aberturas do Object Manager e dos donos de corpos, o token
  (`se/token/access.rs`) e os diretórios do namespace usam essa avaliação;
  as ACEs da política de um corpo são mapeadas pelo tipo antes (como o
  SeAssignSecurity as grava).
- **O descritor de cada objeto** (`ob/object_security.rs`): o do
  OBJECT_HEADER (SeDefaultObjectMethod), o da tabela lateral (dispositivos e
  drivers) ou o que o dono do corpo guarda (processos, threads, tokens,
  objetos de despacho, diretórios e links, seções, callbacks, contextos de
  silo; as chaves no nó do registro). `object_policy` o lê para as
  aberturas por nome e por ponteiro, a duplicação, o ObCheckObjectAccess, o
  ZwQueryObject e o Nt/ZwQuerySecurityObject (que passa pelo
  SecurityProcedure de cada tipo: IRP_MJ_QUERY_SECURITY nos arquivos, o
  DEVICE_OBJECT, o nó da chave, o SeQuerySecurityDescriptorInfo nos demais).
  Um objeto pode não ter descritor (o SecurityDescriptor nulo do NT, o
  atalho do ObInsertObjectEx 0x652192..0x652201: sem nome, criado sem
  descritor, num tipo sem SecurityRequired; as seções marcam
  `no_descriptor`, e os corpos de `ob/objects/dispatcher.rs` — eventos,
  mutantes, semáforos, portas, timers, pacotes de espera — não guardam
  política nenhuma; um nome dado depois pelo próprio kernel dá o descritor
  do sujeito): a abertura por ponteiro, o handle de usuário e o
  ObCheckObjectAccess concedem o acesso pedido sem SeAccessCheck, como o
  ObpCreateHandle (`has_descriptor`); o Nt/ZwQuerySecurityObject devolve o
  descritor vazio de 0x14 bytes (SeQuerySecurityDescriptorInfo 0x6de652), o
  NtSetSecurityObject dá STATUS_NO_SECURITY_ON_OBJECT
  (SeSetSecurityDescriptorInfoEx 0x695cfa) e o SecurityDescriptorSize do
  ObjectBasicInformation é zero (NtQueryObject 0x70fd78). Os corpos de
  despacho com descritor dividem a cópia da política com os iguais
  (`ob/shared_policy.rs`, contada como as entradas do
  ObLogSecurityDescriptor 0x6d8b90, que saem com o último objeto que as
  usa; autoteste `ntos/test/object_descriptors.rs`). O
  ZwCreateEvent passa o OBJECT_ATTRIBUTES adiante (o descritor explícito de
  um chamador de kernel vale); o evento da vertical blank que o dxgkrnl cria
  como SYSTEM, sem nome nem descritor, abre por ponteiro em UserMode no
  dwm.exe (autoteste `ntos/test/multiprocess/access_control.rs`). O export
  ObOpenObjectByPointer (`open_pointer::open_by_pointer`) só confere os
  HandleAttributes contra o TypeInfo.InvalidAttributes do tipo, sem a
  captura de OBJECT_ATTRIBUTES; o win32k passa 0xC0000000 ali ao abrir as
  seções compartilhadas do DirectComposition.
  O SecurityInformation não é validado: só dá o acesso que o handle precisa
  (o SeQuerySecurityAccessMask e o SeSetSecurityAccessMask,
  `se/query_descriptor.rs::query_access_mask` e
  `se/set_security.rs::set_access_mask`), e cada parte desconhecida fica
  fora do descritor devolvido.
  O Nt/ZwSetSecurityObject (`set_object_security`) mescla as partes pedidas
  no descritor corrente (SeSetSecurityDescriptorInfo com o mapeamento do tipo
  e o dono validado pelo token efetivo) e grava o resultado no mesmo lugar
  (`ObjectOwner::set_security`), então a abertura seguinte segue o descritor
  novo. Objetos novos recebem o SeAssignSecurity (`assign_new`: o descritor
  explícito, o dono, o grupo e a DACL padrão do token efetivo, as validações
  de UserMode do dono e da SACL); um objeto nomeado herda as ACEs herdáveis
  do diretório (OBJECT_INHERIT, ou CONTAINER_INHERIT para diretórios) quando
  a DACL dele veio do token, no ObInsertObject (o ParentDescriptor do
  ObpAssignSecurity), no NtCreateDirectoryObject/NtCreateSymbolicLinkObject
  e na publicação do nome pelo `object_manager::create_object`.
- **MDLs**: o IoAllocateMdl (`io/mdl.rs`) só descreve o buffer (Size,
  StartVa, ByteOffset, ByteCount e MDL_ALLOCATED_FIXED_SIZE até 17 páginas) e
  o liga ao IRP; os PFNs e os outros flags vêm de quem descreve as páginas
  (`mm/mdl.rs`): o MmBuildMdlForNonPagedPool (MDL_SOURCE_IS_NONPAGED_POOL e a
  VA de sistema, sem travar), o MmProbeAndLockPages (MDL_PAGES_LOCKED,
  MDL_WRITE_OPERATION numa operação de escrita e o Process: o processo
  sondado, o anexado durante um KeStackAttachProcess, num buffer de usuário,
  nulo num de sistema), o
  IoBuildPartialMdl (os bits herdáveis da origem e a VA deslocada) e o
  MmMapLockedPagesSpecifyCache (MDL_MAPPED_TO_SYSTEM_VA). Em KernelMode, o
  MmMapLockedPagesSpecifyCache de um buffer de usuário mapeia os PFNs do
  MDL em PTEs de sistema (`mm/system_ptes.rs`, o MiReserveSystemPtes, na
  janela SYSTEM_PTE_BASE..TOP): a VA de usuário só vale no processo dono, e
  um driver que completa o pedido no contexto de outro processo (o
  ksecdd.sys com o pedido pendente do lsass) grava pela VA de sistema. Um
  buffer de kernel já está no espaço de sistema e volta como está. O
  MmUnmapLockedPages e o MmUnlockPages devolvem as PTEs; um MDL parcial que
  herdou a VA da origem não as solta. Os pedidos com DO_DIRECT_IO e
  METHOD_*_DIRECT do I/O Manager fazem IoAllocateMdl + MmProbeAndLockPages:
  MDL_PAGES_LOCKED, o Process dono e os PFNs, sem VA de sistema (o driver
  pede a VA pelo MmGetSystemAddressForMdlSafe), e o fim do pedido desfaz o
  mapeamento antes de soltar as páginas.
- **Filas de dispositivo e StartIo**: a KDEVICE_QUEUE é do Ke
  (`ke/device_queue.rs`, os sete KeInsert*/KeRemove*DeviceQueue com o
  layout x64 do NT, inclusive o Hint do KeRemoveByKeyDeviceQueue no qword
  do Busy), e o I/O Manager só a usa (`io/controller.rs`): o
  IoAllocate/FreeController na DeviceWaitQueue do CONTROLLER_OBJECT e o
  IoStartPacket/IoStartNextPacket(ByKey) na DeviceQueue do DEVICE_OBJECT,
  com o spin lock de cancelamento, DOE_SIO_NO_CANCEL e o laço adiado de
  DOE_SIO_DEFERRED (StartIoCount/StartIoFlags/StartIoKey da
  DEVOBJ_EXTENSION), como o IopStartNextPacketByKeyEx.
- Estado global fica atrás de `SpinLock` (`rtl::sync`). Estado lido muito e
  mudado em operações longas, como um volume NTFS, fica atrás de
  `SharedLock`, o papel do ERESOURCE: leituras compartilhadas, mutações
  exclusivas, readquirível por quem já o possui.
- **Átomos e heap do Rtl** (`rtl/atom.rs`, `rtl/heap.rs`): a tabela de
  átomos é a `_RTL_ATOM_TABLE` real em pool (assinatura, push lock, baldes,
  entradas com contagem e fixação); só o índice de handle de cada átomo de
  string (0xC000 | índice) mora num registro do OpenNT por tabela, no lugar
  da tabela de handles. Os serviços de átomos globais (NtAddAtom[Ex],
  NtFindAtom, NtDeleteAtom e NtQueryInformationAtom, `ex/global_atom.rs`,
  do GlobalAddAtom e do SetProp com nome) pedem a tabela ao callout 2 do
  win32k (sem ela, STATUS_ACCESS_DENIED), copiam o nome de modo usuário
  para o kernel e operam com essas rotinas. O heap segue os dois caminhos de criação do
  RtlCreateHeap: o heap fixo (HEAP_CREATE_SEGMENT_HEAP, o desktop heap do
  win32k) sobre a memória do chamador, com cada página nova confirmada pela
  CommitRoutine de RTL_HEAP_PARAMETERS, e o heap NT (memória do processo
  corrente ou do chamador, Lock, segmentos novos do HEAP_GROWABLE, exceção
  STATUS_NO_MEMORY com HEAP_GENERATE_EXCEPTIONS). O handle é o HeapBase,
  com o cabeçalho e as assinaturas reais; a contabilidade dos blocos (16 em
  16 bytes, alinhados a 16) fica fora da memória do heap, num registro do
  OpenNT, e a CommitRoutine é chamada sem nenhuma trava do Rust retida.
  Teste: `ntos/test/rtl_atom_heap_nls.rs`.
- **Listas de faixas e descritores de recursos** (`rtl/range_list.rs`,
  `rtl/resource_encoding.rs`): a RTL_RANGE_LIST é a real (entradas
  `_RTLP_RANGE_LIST_ENTRY` de 0x38 bytes em pool paginado 'RRle'), com a
  lista de topo ordenada e sem sobreposição e as faixas fundidas
  (sublista ordenada por início) do ntoskrnl; os iteradores entregam o
  RTL_RANGE da entrada e conferem o carimbo da lista. A codificação dos
  descritores de memória grandes (CmResourceTypeMemoryLarge, formas de 40,
  48 e 64 bits) segue as Rtl*MemIoResource. Teste:
  `ntos/test/rtl_ranges_resources.rs`, com os valores calculados
  executando o código do ntoskrnl num emulador.
- **KTIMER2** (`ke/timer2.rs`): o `_KTIMER2` do chamador com Callback e
  contextos codificados pelos segredos do boot, TypeFlags e
  CollectionIndex da KiTimer2Combinations e o byte de bandeiras do Header
  (Inserted, Expiring, CancelPending, Running, Disabled). Os inseridos
  ficam numa fila do módulo (o papel das coleções de árvores do NT) que o
  pump dos timers expira: SignalState 1 (Timer2Notification/Synchronization
  nas esperas de `ke/dispatcher.rs`), periódico de volta para agora +
  Period e o callback em DISPATCH_LEVEL. O KeDisableTimer2 (interno) marca
  Disabled, tira da fila com Cancel e finaliza (DisableCallback com o
  DisableContext, em DISPATCH_LEVEL) quando o timer sai da fila e do
  vencimento em curso.
- **EX_TIMER** (`ex/timer.rs`): o EX_TIMER de 0xA0 bytes do 19041 começa
  num KTIMER2 (notificação com EX_TIMER_NOTIFICATION, senão sincronização;
  HIGH_RESOLUTION e NO_WAKE no TypeFlags), seguido do DeleteCallback e do
  DeleteContext codificados e do ExpTimerFreedCookie. O ExSetTimer recebe o
  período como LONGLONG em 100 ns e chama o KeSetTimer2; um EX_TIMER sem
  callback é um objeto de espera (o vsync emulado da fila de blits do
  dxgkrnl espera nele a cada período). O ExDeleteTimer desabilita o KTIMER2
  com o ExpFinalizeTimerDeletion, que roda o DeleteCallback, inverte o
  cookie e libera o EX_TIMER. Atributos, prazos e parâmetros inválidos dão
  os bugchecks 0xC7 e 0xC6 do original. Teste:
  `ntos/test/platform_support.rs`.
- **Errata Manager** (`em/`): o banco do `\SystemRoot\INF\errata.inf`
  desta máquina, os provedores e a avaliação das regras, como no ntoskrnl
  19041. O carregador entrega a imagem do INF (o EmInfFileImage do
  LOADER_PARAMETER_EXTENSION): o OpenNT a lê do volume de boot logo depois
  de montá-lo (`em::loader_inf_image`) e o EmInitSystem a interpreta com o
  interpretador de INF do Cm (`cm/inf_parse.rs`, o CmpParseInfBuffer:
  tokens, seções, linhas, continuação e `%nome%` da [Strings]) e o
  EmpParseInfDatabase (`em/parse.rs`): tipos de entrada, callbacks com as
  contagens de argumentos do [CallbackDef], regras com a expressão
  pós-fixa do [Rule] (`?Callback(c)(n)(e)`, `%Regra(...)`, `&`, `|`, os
  índices decimais validados contra a regra que contém o termo; uma regra
  só referencia as definidas antes), a tabela de cadeias e as regras-alvo
  com os conjuntos de argumentos (cadeias pelo nome da chave em [Strings],
  números hexadecimais do RtlCharToInteger). Depois registra os callbacks
  da HAL (`hal/errata.rs`: OEMID, OEM Table ID e revisões das tabelas ACPI
  e o IAPC_BOOT_ARCH da FADT) e os embutidos (`em/builtin.rs`: data do
  BIOS do endereço físico 0xFFFF5 no boot por BIOS, CPU da KPRCB,
  arquitetura, sempre verdadeiro/falso); o banco fica sob o
  EmpDatabaseLock (um `SharedLock` exclusivo, que os callbacks dos drivers
  atravessam). O EmProviderRegister liga as rotinas dos drivers aos
  callbacks (outra rotina no mesmo callback colide) e conta os provedores
  dos tipos; cada registro enfileira a atualização das regras que os usam,
  que o work item do Errata Manager processa (`em/evaluate.rs`:
  EmpUpdateRuleState, prontidão por provedores, rotinas e regras
  referenciadas). O EmClientQueryRuleState atualiza e avalia a regra-alvo
  (a avaliação UNKNOWN vira FALSE) e o EmClientRuleEvaluate avalia com as
  entradas do chamador e devolve o estado cru; a avaliação percorre os
  conjuntos, com `&`/`|` em curto-circuito, os índices remapeando os
  argumentos e o callback do driver chamado na ABI do EM_CALLBACK_ROUTINE.
  No QEMU, as regras de máquina da FADT (OEMID "BOCHS ") são FALSE; o
  pci.sys, o acpi.sys e o ataport.sys recebem as respostas reais e o pci.sys
  avalia as regras de PCIDevice com os callbacks dele.
- **Jobs** (`ps/job.rs` e `ps/job/`): o EJOB real (o corpo de 0x640
  bytes do ObCreateObject com PsJobType, CloseProcedure PspJobClose e
  DeleteProcedure PspJobDelete pelas rotinas privadas), na PspJobList e com
  JobId; `object` cria, abre, fecha (KILL_ON_JOB_CLOSE termina a hierarquia
  e a porta é desassociada no último handle) e apaga; `membership` faz a
  atribuição pelas disposições do PspGetJobAssignmentDisposition (sem job,
  já no job, descer para um descendente, aninhar um job vazio sob o do
  processo: a hierarquia do Windows 8, com ParentJob, RootJob,
  NestingDepth e o vetor de ancestrais), os limites da cadeia (processos
  ativos: STATUS_QUOTA_EXCEEDED e ACTIVE_PROCESS_LIMIT), os contadores e
  NEW_PROCESS, a herança na criação (o `on_created` do NtCreateUserProcess:
  PspImplicitAssignProcessToJob com BREAKAWAY_OK/SILENT_BREAKAWAY_OK e
  PROCESS_CREATE_FLAGS_BREAKAWAY, e a JobList), a saída (EXIT_PROCESS ou
  ABNORMAL_EXIT_PROCESS nas rotinas de saída de processo; depois do
  KPROCESS sinalizado, a contabilidade somada a cada job e
  ACTIVE_PROCESS_ZERO), a deleção (o job solto no PspProcessDelete), o
  NtTerminateJobObject e o NtIsProcessInJob; `limits` faz os limites
  efetivos de um job aninhado, o teto de commit de cada processo
  (EPROCESS.CommitChargeLimit) e o commit do job
  (PspChangeJobMemoryUsageByProcess, com JOB_MEMORY_LIMIT); `information`
  responde às classes de consulta e alteração. O commit privado de cada
  processo (EPROCESS.CommitCharge, `mm/process_commit.rs`, o
  MiChargeFullProcessCommitment e o MiReturnFullProcessCharges) é cobrado
  pelas páginas privadas que o NtAllocateVirtualMemory comita e pelas
  regiões que o kernel monta (pilha, PEB, TEB), e devolvido no decommit, na
  liberação e no fim do espaço; acima do teto do processo ou do limite do
  job o commit é STATUS_COMMITMENT_LIMIT. Ficam registrados no job, sem
  efeito no escalonador, os limites de tempo, working set, afinidade,
  prioridade e classe de escalonamento; o controle de CPU, de rede e de
  E/S, o congelamento e os silos respondem STATUS_NOT_SUPPORTED. As
  notificações vão para a IOCP fora da trava dos jobs (o `Outbox`). Teste:
  `ntos/test/multiprocess/jobs.rs` (`JOBS_OK`).
- **ETW** (`ntos/etw/`): um registro único de provedores
  (`provider_state.rs`): uma ETW_GUID_ENTRY do pool por GUID, silo e tipo
  (provedor de trace ou GUID de notificação), com os oito TRACE_ENABLE_INFO
  das sessões e o ProviderEnableInfo agregado que o EtwEventEnabled e o
  EtwProviderEnabled leem; cada registro é um ETW_REG_ENTRY no RegListHead
  dela. Os de kernel (EtwRegister, EtwRegisterClassicProvider) vêm do pool
  e recebem as mudanças pela rotina de habilitação nativa; os de modo
  usuário (`user_registration.rs`) são o corpo de um objeto
  EtwRegistration criado pelo NtTraceControl 15 (EtwpRegisterUMGuid) com o
  handle na tabela do processo, apagados pela DeleteProcedure quando a
  ntdll fecha o handle, e recebem as mudanças como pacote
  ETWP_NOTIFICATION_HEADER na fila do processo (o EPROCESS.EtwDataSource
  guarda o evento que o EtwAddNotificationEvent registrou; a ntdll lê o
  pacote pelo NtTraceControl 16 e chama o callback do EventRegister). As
  sessões (`logger.rs`, NtTraceControl 1-7) têm buffers de verdade
  (WMI_BUFFER_HEADER e registros EVENT_HEADER com HeaderType 0xC013, itens
  estendidos e dados), Flush e Stop, e uma thread do logger cada (o
  EtwpLogger, com o LoggerThreadId na consulta); EtwWrite/EtwWriteTransfer/
  EtwWriteEx/EtwWriteString e o NtTraceEvent 0x300 da ntdll entregam só às
  sessões cujo nível e keywords aceitam o evento; um segmento ilegível de
  um chamador de kernel vai zerado no evento, como a cópia sob __try do
  EtwpEventWriteFull. Numa sessão de tempo
  real a thread acorda a cada buffer cheio, a cada flush pedido e a cada
  FlushTimer e entrega os buffers cheios aos consumidores de tempo real
  (`realtime.rs`): o NtTraceControl 11 (EtwpRealtimeConnect) cria o objeto
  EtwConsumer com o espaço reservado, o bitmap, a lista e os eventos que o
  sechost passa; a thread, anexada ao processo do consumidor, copia cada
  buffer na primeira faixa livre do espaço (ou em páginas novas), põe o
  SlistEntry na lista, sobe o contador e sinaliza o evento de dados, com o
  marcador vazio depois do flush nas sessões por processador; o 14 e o
  fechamento do handle desligam o consumidor (o evento de desligamento).
  Sem consumidor, os buffers cheios ficam guardados na sessão e vão ao
  primeiro que conectar, no lugar do arquivo `RtBackup` do NT. O NtTraceControl 24 (o
  EtwpRegisterSecurityProvider) registra o primeiro processo como provedor
  de eventos de segurança (o lsass.exe, pelo EtwRegisterSecurityProvider do
  AdtpInitializeAuditingCommon); um segundo registro dá
  STATUS_ACCESS_DENIED. O NtTraceEvent 0x500 (o EtwWriteUMSecurityEvent)
  só aceita esse processo e vai às sessões de segurança, que o OpenNT não
  tem: o evento é aceito sem destino. EtwSetInformation guarda os
  traits validados (STATUS_FILE_CORRUPT_ERROR mal formados) e liga o tipo
  dos descritores; EtwActivityIdControl usa o TEB.ActivityId da thread
  (thread de sistema: STATUS_NOT_SUPPORTED) e a semente do
  KPRCB.EtwSupport para IDs novos. O despacho do NtTraceControl valida os
  43 códigos como o 19041. O EnableTraceEx2 de modo usuário (17 com o tipo
  EtwNotificationTypeEnable) habilita, desabilita ou pede a captura de
  estado do provedor na sessão do LoggerId pelo mesmo EtwEnableTrace (sem
  os descritores de filtro); o 21 lista os GUIDs das entradas de provedor
  e os 10 do global logger de modo usuário; o 25 devolve o ETW_REF_CLOCK
  {StartTime, StartPerfClock} gravado no início da sessão. Ficam sem
  implementação (STATUS_INVALID_DEVICE_REQUEST depois da validação) as
  outras notificações do 17, as respostas a notificações (18 e 19), a
  informação de um GUID e a enumeração (22 e 23), as listas de grupos e de
  exclusão, WDI, compressão e sessões privadas, que nenhum processo do boot
  usa; os grupos de provedores dos traits, os eventos de imagem do
  EtwTrackProviderBinary e os loggers clássicos por TRACEHANDLE (NtTraceEvent
  0x200) também não existem. Os autologgers do Registro (`autologger.rs`, o
  EtwpInitializeAutoLoggers da fase 1, depois das hives) iniciam cada
  sessão de `Control\WMI\Autologger` com Start, com as propriedades da
  chave, habilitam os provedores das subchaves (Enabled, EnableLevel,
  MatchAnyKeyword, MatchAllKeyword, EnableProperty) e gravam o Status de
  cada chave; o arquivo da sessão e o RtBackup não existem. Diagnóstico
  (`diagnostic.rs`, só serial): cada evento do provedor do Service Control
  Manager que alguma sessão aceita sai como `[scm] evento <Id> <campos>`
  (no boot da cadeia, pela EventLog-System), com os começos e paradas de
  serviço e as falhas 7000-7045 do services.exe. Testes:
  `etw_trace_session`, `etw_user_registration` e `etw_realtime` (com os
  autologgers e o diagnóstico `[scm]`) na fase 6;
  o marcador `ETW_USER_REGISTRATION_OK` no boot do smss real.
- **Trava e energia do KD** (`kd/power.rs`): KdDebuggerLock em
  DISPATCH_LEVEL, a lista dos tratadores de energia do transporte e, com o
  KdPitchDebugger de um boot sem depurador, KdPowerTransitionEx sem efeito
  e KdDisableDebugger com STATUS_DEBUGGER_INACTIVE; com o depurador do
  OpenNT, a transição do ntoskrnl (bit 30 força, D0 reprograma a UART,
  D1-D3 sem efeito, outro estado recusado). DbgCommandString é o serviço 5
  do `int 0x2D` num corpo nativo.
- **Depurador do kernel** (`kd/`): código do próprio OpenNT. Liga com
  `--kd=com2` (`com3`, `com4`; a COM1 é o log). Sem a opção, o boot é o de
  um Windows sem /DEBUG (KdPitchDebugger).
  - Transporte (`kd/transport.rs`): a fase 0 programa a UART com E/S
    programada, sem IRQ. A FIFO fica intocada para não perder um pedido que
    chegou antes; a sessão a liga (gatilho de 14 bytes) no primeiro pacote,
    quando o host espera a resposta. Com ela, cada lote de 16 bytes sai num
    `rep outsb` depois de um THRE (cerca de 9 µs por byte no WHPX, contra
    42 µs de uma leitura do LSR e um OUT por byte), e tudo o que vai ao
    host usa a compressão `X*n` do protocolo.
  - Estado visto pelos drivers (`kd/debugger.rs`), como o KdInitSystem com
    transporte: KdDebuggerEnabled e o bit 0 do
    KUSER_SHARED_DATA.KdDebuggerEnabled ligados; KdComPortInUse com a porta;
    KdDebuggerNotPresent TRUE até um host trocar pacotes (então FALSE, com o
    bit 1). KdDisableDebugger, KdEnableDebugger, KdChangeOption e
    KdRefreshDebuggerNotPresent seguem a lógica do ntoskrnl (KdDisableCount,
    KdPreviouslyEnabled, KdBlockEnable, recusa com KernelDr7 habilitado).
  - Protocolo (`kd/packet.rs`, `kd/session.rs`): o protocolo remoto do GDB.
    Cada processador é uma thread do protocolo. `g`/`G`/`p`/`P` usam o
    quadro do trap (`kd/registers.rs`: a ordem do GDB para x86-64, x87/SSE
    da área FXSAVE64). `m`/`M`/`X` andam nas tabelas de páginas do CR3 do
    processador pelo mapa direto, sem travas nem faltas (`kd/memory.rs`).
    `Z0` grava o 0xCC pelo quadro físico; `Z1`/`Z2`/`Z4` são DR0-DR3
    (`kd/breakpoints.rs`, publicados em KPRCB.ProcessorState.SpecialRegisters).
    `qXfer:libraries:read` dá a lista de módulos ao GDB. `x` lê memória em
    binário (o `binary-upload` do GDB: metade dos bytes do `m`), em pacotes
    de 16 KB. A resposta de parada leva os 24 primeiros registradores do `g`
    (os adiantados do GDB), a impressão digital da lista de módulos
    (`modgen:`) e o EPROCESS corrente do processador (`process:`): o cliente
    decide a parada sem `g`, sem `monitor lm` e sem `.process`.
  - Consultas pelo `qRcmd` (o `monitor` do GDB): `kd/monitor.rs` lista
    processos e threads pelas listas nativas, os registradores de uma thread
    fora da CPU pelo quadro de troca (sem ele, KernelStack = InitialStack:
    uma thread de usuário fora de um serviço, numa espera adiada ou no fim
    do intervalo, pelo CONTEXT do anel 3, com a TEB e a faixa da pilha de
    usuário do NT_TIB), módulos, processadores com IRQL e
    thread corrente, objeto por nome, o anel do DbgPrint, breakpoints e o
    bugcheck (código, nome do KiBugCodeMessages e o driver de um parâmetro).
    `kd/inspect.rs` mostra objetos do NT com os layouts do PDB
    (`inc::types`): `process` (EPROCESS e as threads), `thread` (estado,
    motivo da espera, prioridades, pilha de kernel, IRPs pendentes), `irp`
    (os campos e cada IO_STACK_LOCATION com major/minor, dispositivo,
    arquivo, rotina de conclusão e parâmetros), `devobj` (DEVICE_OBJECT e a
    pilha de dispositivos por AttachedDevice e AttachedTo), `drvobj`
    (DRIVER_OBJECT, os dispositivos e a tabela de despacho) e `handle` (a
    entrada da HANDLE_TABLE nativa, pelo caminho do
    ExpLookupHandleTableEntry).
  - Fim de um processo de usuário (`kd/terminate.rs`, `monitor kill
    <pid|end> <código>`): com a máquina parada o comando só acha o processo
    pelas listas nativas e guarda o pedido em duas células atômicas, sem
    trava nenhuma. Com o depurador ligado, o boot reserva um work item do
    kernel e o deixa na fila com o pedido como predicado de prontidão:
    depois que a máquina segue, a gerência das filas acorda uma worker, que
    chama o PspTerminateProcess (`ps::create::exit_process`) a
    PASSIVE_LEVEL, como um NtTerminateProcess de outro processo, e devolve o
    item à fila. Processos de sistema ficam de fora. É o que o roteiro do
    teste reinicio-do-shell usa para derrubar o explorer.exe.
  - Rastro de instruções (`kd/trace.rs`): o host arma com `monitor trace
    start` (número de instruções, endereço final, até o retorno,
    profundidade máxima, faixas puladas, entrar ou sair de uma faixa,
    endereço vigiado) e continua. O processador da parada executa passo a passo
    (TF) e cada #DB grava um registro compacto num buffer de 256 KB
    (reservado no `kd::initialize` só com `--kd`, fora da imagem do kernel,
    que tem teto fixo: `KERNEL_IMAGE_MAX`): classe
    da instrução (call, ret), RIP, profundidade, thread quando muda, valor
    vigiado quando muda e só os registradores que mudaram. Não há volta ao
    host por instrução. O lote para no fim pedido, num breakpoint, antes de
    `iretq`/`sysret`/`hlt`/`int` ou com o buffer cheio (`trace resume`
    continua). O host lê o buffer por `qOpenNTTrace:offset,tamanho`. Os
    outros processadores ficam congelados e as interrupções mascaradas, como
    no passo comum. O formato é o de `tools/opennt-kd/src/trace.rs`.
  - Paradas (`kd/stop.rs`), pelos trampolins (`hal/amd64/irqstubs.rs`):
    `int 3` e #DB do anel 0 antes do SEH (o KiDebugRoutine); o tique do
    relógio no anel 0 consulta o LSR (o 0x03 do host, ou o começo de um
    pacote, para a máquina, como o KdPollBreakIn); a exceção sem tratador e
    o KeBugCheckEx param antes do diagnóstico e da tela de STOP; o pânico
    para antes de travar. A entrada do depurador confere o GS pelo MSR, como
    o KiNmiInterrupt: um passo parado entre o `swapgs` e o `iretq` de volta
    ao anel 3 entra com o GS do usuário.
  - Parada por NMI (o `nmi` do monitor do QEMU): é a que funciona com as
    interrupções desligadas, quando o tique do relógio não vem. Com o
    depurador ligado, a NMI do BSP tem caminho próprio (`irq_nmi`) e nunca
    vira exceção (antes, uma NMI no anel 3 matava o processo com
    STATUS_ACCESS_VIOLATION e no anel 0 caía no diagnóstico fatal). O
    tratamento segue o KiProcessNMI do 19041 (0x5129b0): o congelamento
    primeiro (KiCheckForFreezeExecution), a marca de NMI em andamento do
    processador (KiNmiInProgress) e a KiNMILock tomada sem esperar, com o
    congelamento conferido enquanto outro processador a tem. No lugar do
    HalHandleNMI (relatório do WHEA e bugcheck), a NMI é o pedido de parada
    do host: a resposta leva `nmi:` e continuar volta ao código
    interrompido. Do anel 3, a parada mostra o quadro do usuário (seletores
    e GS dele); um passo dali segue na thread de usuário. A NMI que chega no
    anel 0 com o GS do usuário (logo depois do SYSCALL, antes da troca de
    pilha, ou entre o `swapgs` e o `iretq`) fica para o próximo tique do
    relógio no anel 0. `monitor nmi` mostra os contadores e o estado de cada
    processador.
  - Congelamento: o processador da parada congela os outros com NMI
    pelo código de IPI do Ke (`smp::send_nmi_to_application_processors`; a
    NMI dos APs prende o processador em `rs_kd_freeze_processor` com o
    quadro publicado) e só os degela ao continuar. KPRCB.IpiFrozen leva o
    estado com os valores do 19041: 4 no dono, 5 no alvo pendente, 2 no
    preso, 3 no degelo, 0 rodando. Os APs não têm `int 3` (a IDT deles só
    tem o portão da NMI, e um `int 3` ali era falta tripla): um bugcheck, um
    pânico, um DbgBreakPointWithStatus ou o 0x03 lido num DbgPrint de um AP
    viram um pedido ao BSP por NMI, e a parada mostra o AP (`thread:` dele;
    a thread 0 do protocolo é o processador da parada). O passo é recusado
    nessa parada.
  - Passo: roda só no processador da parada, com o IF mascarado durante a
    instrução. O IF original volta depois, e um `pushfq` passo a passo grava
    o IF original. Continuar de um breakpoint dá antes um passo com o byte
    original. O passo sobre `hlt` (que dormiria com o IF mascarado) pula a
    instrução. O passo sobre o `iretq` (ou o `swapgs` antes dele) de volta
    ao anel 3 liga o TF no quadro do IRETQ, solta a parada e para no #DB do
    anel 3 da thread do intervalo (antes, o #DB ia ao processo como
    STATUS_SINGLE_STEP e a máquina ficava com os outros processadores
    congelados).
  - Passo de usuário (`kd/user_debug.rs`): o TF no CONTEXT da thread, com um
    passo pendente por thread. O #DB dele é do depurador também quando o
    passo para a máquina (o `s` numa parada de usuário, ou o passo do anel 0
    que seguiu para o anel 3) e o host continua depois: só um `C sig`
    explícito o entrega ao processo. O `pushfq` passo a passo empilha o
    RFLAGS sem o TF (o RtlCaptureContext começa assim). Uma exceção da
    própria instrução que vai ao processo, ou uma APC de usuário que desvia
    o CONTEXT, desfaz o passo antes da cópia do CONTEXT para a pilha de
    usuário: o TF não volta depois pelo NtContinue, e o breakpoint suspenso
    volta.
  - Robustez da sessão (`kd/recovery.rs`): cada pacote do host roda com um
    ponto de recuperação (um `setjmp` próprio, em assembly). Uma falta sem
    tratador, um KeBugCheckEx ou um pânico dentro de um comando abandonam o
    comando; o host recebe o motivo (no texto do `monitor`, ou em pacote `O`
    antes de um `E0F`) e a sessão segue. O código abandonado não roda
    destrutores: a mensagem conta as travas que ficaram tomadas. O `int 3`
    de um breakpoint do host que um comando atinge executa o byte original,
    que volta no fim da sessão. Uma falta sem tratador no meio de um passo
    encerra o passo e vira uma parada nova; a exceção de kernel sem tratador
    retoma se o host mudar o RIP (ou pedir um passo), e segue o diagnóstico
    se ele só continuar. A falta dupla e o machine check nunca retomam.
  - Nada da parada aloca nem toma trava. As consultas que usam estruturas
    do Rust (módulos, objeto por nome) só rodam quando nenhum processador
    parado tinha SpinLock ou SharedLock.
  - O DbgPrint vai ao host como pacote `O` com a máquina rodando
    (`kd/print_log.rs`).
  - Serviço de depuração do modo usuário (`kd/debug_service.rs`). O portão
    0x2D da IDT tem DPL 3, como o KiDebugServiceTrap. Com um host anexado
    (bits 0 e 1 do KUSER_SHARED_DATA.KdDebuggerEnabled), o DbgPrint da
    ntdll faz `int 0x2D` seguido de `int3`. A HAL salva o vetor 0x2D como
    STATUS_BREAKPOINT. O despacho de primeira chance
    (`ps/user/exceptions.rs`) monta o registro do trap (endereço depois do
    `int3`, serviço em ExceptionInformation[0]) e chama o KdTrap antes de
    entregar ao processo. Sem depurador (KdpStub), os serviços 1, 3, 4 e 5
    só pulam o `int3`. Com ele (KdpTrap), o serviço 1 é o KdpPrint: o filtro
    de `kd/debug_filter.rs`, até 512 bytes abaixo de MmUserProbeAddress, o
    anel do DbgPrint e o host, e o status no RAX. O prompt (serviço 2) segue
    ao processo, porque o transporte do OpenNT não o atende. O
    NtQueryDebugFilterState usa o mesmo filtro. Antes, o portão tinha DPL 0
    e o DbgPrint virava STATUS_ACCESS_VIOLATION no processo. Com o
    depurador anexado cedo, o csrss.exe morria assim na thread que inicia o
    RawInputThread: a espera dela numa seção crítica disputada voltava com
    STATUS_TIMEOUT (a PEB saía com CriticalSectionTimeout 0) e a ntdll
    avisava pelo DbgPrint.
  - Processos de usuário:
    - Processo das leituras (`kd/process_context.rs`): `monitor .process
      <pid|eprocess>` troca a raiz de `m`/`M`/`X` e do `Z0` pela
      KPROCESS.DirectoryTableBase do processo, até a máquina seguir. Sem
      argumento, mostra o processo do CR3 do processador.
    - Paradas do anel 3 (`kd/user_debug.rs`): o despacho de primeira chance
      (`ps/user/exceptions.rs::hardware`) chama `user_debug::exception`
      antes da entrega ao processo. O `int 3` de um breakpoint do depurador
      gravado pela raiz deste processo para a máquina; o host vê um quadro
      montado do CONTEXT (CS 0x33, GS = TEB, x87/SSE do FltSave), e o quadro
      volta ao CONTEXT na saída (`stop::enter_user`). O 0xCC vai ao quadro
      físico, e o byte físico (não a VA) identifica o breakpoint de usuário:
      cada `Z0` acrescenta a raiz do processo escolhido aos donos do slot.
      Num quadro de código compartilhado (a ntdll, uma DLL em qualquer VA),
      o `int 3` de um dono para a máquina e o de outro processo passa sem
      parar (`breakpoints::classify_user_hit`), com o byte original de volta
      por um passo da thread; o `z0` tira só o processo escolhido, e o byte
      volta com o último dono. O copy-on-write de uma página de código
      (`breakpoints::page_copied`, chamado pelo NtProtectVirtualMemory que
      torna gravável uma página de imagem e pela falta copy-on-write das
      vistas de dados) leva o breakpoint do processo para a cópia, devolve
      o byte ao quadro compartilhado quando ele era o único dono e tira da
      cópia o 0xCC alheio. A saída do processo (`kd/events.rs`, antes de o
      espaço de endereços ser desmontado) e o desmapeamento de uma vista de
      imagem tiram o processo dos donos. O passo e a saída de um
      breakpoint usam o TF no CONTEXT; o #DB do passo volta pelo mesmo
      caminho e é reconhecido pelo endereço do CONTEXT. `monitor uex on`
      para também nas outras exceções do anel 3 (o FLG_STOP_ON_EXCEPTION do
      KdpReport: sem os códigos informativos até 0x4000001D, o
      STATUS_PORT_DISCONNECTED e os positivos a partir de 0x40000020, como o
      DBG_PRINTEXCEPTION_C do OutputDebugString).
    - Exceções do anel 3 por código (`kd/exception_filter.rs`, `monitor sx
      [e|d|i|r] <código|failfast>`): `e` para nas duas chances, `d` só na
      segunda, `i` nunca; `failfast` vale pelos três códigos de fim imediato
      (0xC0000409, 0xC0000602 e 0xC000027B). A tabela vale por cima do `uex`
      e esvazia quando o host se desliga; sem entrada, a segunda chance não
      para. A primeira chance passa pelo filtro no despacho de hardware e na
      exceção levantada pelo NtRaiseException (o RaiseException, as
      exceções do C++ e do RPC). A segunda chance é o ponto do
      DbgkForwardException(SecondChance) do 19041, com o depurador do kernel
      no papel da porta de depuração: o NtRaiseException com FirstChance
      FALSE, a exceção que não pôde ser entregue e o `__fastfail` (`int
      0x29`), que o KiFastFailDispatch (0x412280) leva direto à segunda
      chance com o registro (STATUS_STACK_BUFFER_OVERRUN, não continuável, o
      código do RCX em ExceptionInformation[0]); a HAL agora salva o CONTEXT
      do `int 0x29` e o despacho termina o processo sem entregar a exceção.
      O fim do processo pelo NtTerminateProcess com um código da tabela
      também para: o RaiseFailFastException sem o serviço do WER termina
      assim, com o código. A resposta leva `exception:código;chance:n;` (e
      `term:` no fim do processo). A segunda chance e o fim do processo são
      só para ver: continuar deixa o processo terminar, e o passo é
      recusado. `monitor exr` mostra a última exceção relatada: o registro,
      o processo, o código do fast fail (FAST_FAIL_*) e, num 0xC000027B, as
      STOWED_EXCEPTION_INFORMATION do vetor (ResultCode, endereço ou texto).
      Antes de gravar num endereço de usuário, o byte atual é conferido; antes
      de devolver um byte de usuário, também (tem de ser o 0xCC). Os
      comparadores de hardware do depurador valem só no anel 0: na entrada do anel 3 a HAL
      troca o banco de depuração pelo da thread (o CONTEXT dela).
    - Breakpoints de hardware de usuário (`kd/user_hardware.rs`): um
      `Z1`/`Z2`/`Z4` num endereço de usuário com processo escolhido arma o
      comparador no CONTEXT de cada thread do processo (DR0-DR3 e DR7, o
      mesmo índice em todas). O #DB do anel 3 que cita esse comparador, na
      thread de um processo com a mesma raiz, para a máquina. Continuar de
      um comparador de execução desliga o comparador por um passo da thread.
      Os comparadores voltam às threads a cada continuação (as criadas
      depois os recebem na parada seguinte); `monitor uhw` lista.
    - Breakpoints de memória por página (`kd/page_breakpoints.rs`,
      `monitor membp set <início> <tamanho> <a|w|x>`): o bit reservado 51 na
      PTE de cada página (CPUs com MAXPHYADDR menor que 52). O #PF com RSVD
      não é atendido pelos provedores do Mm e chega ao depurador antes da
      entrega ao processo. A página volta ao normal, o tipo pedido é
      conferido pelo código de erro e a instrução executa num passo antes de
      o bit voltar. A proteção da região (VAD) não muda. A parada leva
      `membp:endereço`. Limites: uma leitura do kernel na página falha como
      violação de acesso; a saída do processo desarma as páginas dele.
    - Registradores além do `g` (`kd/extended_state.rs`, só por `p`):
      `ymm0h`-`ymm15h` (59-74): numa parada do kernel, pelo XSAVE do
      componente AVX na CPU da parada; numa parada de usuário, da área com o
      estado de usuário da thread (`ke::xstate::user_state_area`); DR0-DR3,
      DR6 e DR7 (75-80), os do CONTEXT numa parada de usuário e o conjunto do
      depurador numa parada do kernel.
    - Eventos (`kd/events.rs`): as notificações do Ps (`ps/notify`) chamam
      `opennt_kd_process_event`, `opennt_kd_thread_event` e
      `opennt_kd_image_event` (sysv64, argumentos nos registradores) antes de
      olhar as rotinas registradas. O host arma breakpoints nelas e lê os
      argumentos. Para as cargas de imagem há o filtro do host
      (`QOpenNTLoadBreak:nome;nome...`, `*` = qualquer): só uma carga cujo
      nome-base, ou ele sem a extensão, está no filtro para a máquina, em
      `opennt_kd_load_break` com os mesmos argumentos, e a resposta de parada
      leva `library:;load:base,tamanho,pid,nome;`. As outras cargas não param
      (no KD do 19041 cada módulo de sistema custa uma ida e volta ao host).
    - Consultas: `handles` (a HANDLE_TABLE inteira, com o tipo pelo
      TypeIndex e o ObHeaderCookie, o nome pelo NameInfo, pelo FILE_OBJECT
      ou pelo ImageFileName, e o tipo da tabela de usuário quando a linha
      nativa não o dá), `vad` (as regiões do `ProcessState`: base, tamanho,
      tipo, proteção, nome), `uthreads` (TEB, início, CONTEXT salvo,
      RIP/RSP, estado, motivo da espera, LastError, prioridade, suspensão,
      tempos de kernel e de usuário e ciclos do KTHREAD) e `kmap` (as faixas
      fixas do espaço de sistema). As listas são paginadas (`mais: N`);
      `vad` e `uthreads` só rodam com as travas livres.
  - Fluxo de registros (`kd/stream.rs`): um anel de 1024 posições de 384
    bytes, reservado com `--kd`. Quem grava pega o número de sequência,
    zera o selo da posição, copia o registro e grava o selo com o número
    + 1; quem lê confere o selo antes e depois da cópia. Com `monitor
    stream on` e a máquina rodando, o gravador manda os pendentes ao host
    num pacote `O` (conteúdo `\0OSTR`, versão, registros) quando o lote
    passa de 24 registros ou de 25 ms, se a trava do transporte estiver
    livre (no máximo três pacotes por vez). Parado, o host lê por
    `qOpenNTStream:SEQ` (cabeçalho com o próximo número, o mais antigo, os
    perdidos e as flags, e os registros a partir de SEQ); o pedido não muda
    o estado.
  - Monitor de APIs (`kd/api_monitor.rs`, `monitor api`): o gancho no
    `init::exports::dispatch` lê um booleano quando tudo está desligado.
    Ligado, filtra pelo endereço de retorno (até 8 faixas de módulos ou
    todos os chamadores) e grava, na volta do provedor, o id do export, os
    argumentos (quantos o host disse em `api spec ID:ARGC[:ARG:TIPO]`;
    sem especificação, quatro), PID, TID, ETHREAD, retorno, duração e
    resultado, e até dois argumentos copiados (UNICODE_STRING,
    ANSI_STRING, texto UTF-16 ou ASCII, o ObjectName de OBJECT_ATTRIBUTES,
    o qword de um ponteiro de saída) pelo leitor do depurador, sem faltas.
    `api names` dá os nomes da tabela. Os exports com corpo x64 próprio
    (`native_export_layout`) e as rotinas privadas não passam pelo
    despacho.
  - Rastreador de IRPs (`kd/irp_trace.rs`, `monitor irptrace`): ganchos
    no `io_manager::iof_call_driver` (antes e depois da rotina de
    despacho), no `iof_complete_request` (entrada e cada rotina de
    conclusão), no `irp_builder::free_irp` e, pelo despacho dos exports,
    na criação por um driver (IoAllocateIrp, IoBuild*Request,
    IoMakeAssociatedIrp). Cada gancho é uma função `#[inline]` que só lê o
    booleano; o corpo é `#[cold]`. O chamador de um IofCallDriver é o
    endereço de retorno do export em curso no processador (guardado pelo
    gancho do despacho, com a ETHREAD conferida).
  - Exploradores (`kd/explore.rs`): `reg keys|values|value` lê o
    `cm/registry` (`node_by_path`, `with_node` com as células, `hive_of`),
    seguindo os links; `objdir` lista um diretório do `ob/object_manager` (tipo, corpo
    nativo, filhos, destino do link ou arquivo); `fs ls|read` usa o leitor
    NTFS do kernel (`drivers/fs/ntfs::mounted`, ATA PIO por consulta).
    Todos alocam e tomam as travas do Rust: só rodam com
    `stop::locks_held()` falso. Saída paginada pelo tamanho (`mais: N`),
    campos separados por tabulação. A linha do `qRcmd` aceita 512 bytes.
  - Os APs não armados usam a própria IDT de três vetores (os armados,
    a cópia da do BSP, com a NMI dos APs no vetor 2): só o BSP trata
    `int 3`/#DB, e os comparadores de hardware são carregados só no
    processador da parada.
- **Bugcheck** (`ke/bugcheck.rs`, `ke/bugcheck_reason.rs`,
  `bgk/bugcheck_screen.rs`, `bgk/boot_font.rs`): o KeBugCheckEx segue o
  KeBugCheck2 — KiBugCheckActive (o segundo processador gira até ser
  congelado; o aninhado soma 4 e para), KiBugCheckData, a linha
  `*** STOP (KeBugCheckEx)`, a primeira parada do depurador (pulada no
  0xE2), interrupções desligadas em HIGH_LEVEL, os outros processadores
  presos pela NMI de congelamento do `kd/stop.rs`, a tela
  (KiDisplayBlueScreen), os callbacks de entrada (KbCallbackReserved1), o
  despejo — no OpenNT a serial: os dados secundários dos callbacks de
  motivo e o black box, com o progresso na tela —, os callbacks de
  KeRegisterBugCheckCallback (a LIST_ENTRY da cabeça, conferidos antes de
  rodar) e, pelo `Control\CrashControl` lido no boot (`cm/crash_control.rs`
  semeia AutoReboot 0 e CrashDumpEnabled 7), o reinício ou a parada com a
  segunda chance do depurador. O nome do código sai do KiBugCodeMessages: a
  tabela de mensagens do ntoskrnl.exe da máquina vai para a `.rsrc` do PE
  do kernel no build (`xtask/src/kernel_pe.rs`) e o kernel a acha pelo
  próprio diretório de recursos. A tela é a do BgpFwDisplayBugCheckScreen
  no framebuffer de boot (a tabela de cinco tipos de tela, o fundo
  0x0077D6, os textos do bootres.dll.mui da instalação que o build põe no
  bundle, o ":(" desenhado como texto, sem o código QR) com a fonte de 8x16
  do BIOS de vídeo ampliada com borda suavizada; sem framebuffer, os mesmos
  textos em branco sobre azul no modo texto do Inbv. O KiBugCheckDriver é a
  imagem carregada que contém um dos parâmetros (KiDumpParameterImages). O
  i8042prt.sys tem o CrashOnCtrlScroll ligado: Ctrl direito com Scroll Lock
  duas vezes faz o próprio driver chamar KeBugCheckEx(0xE2), o teste
  `bugcheck`. Logo depois da linha `*** STOP`, antes da parada do depurador,
  o diagnóstico do OpenNT (`ke/bugcheck_trace.rs`, só serial, sem mudar o
  bugcheck) imprime um bloco `[kcrash]`: a origem (a exceção de kernel sem
  tratamento do KMODE_EXCEPTION_NOT_HANDLED, anotada pelo despacho de
  exceções, com o tipo de acesso e o endereço que faltou; senão a chamada
  nativa ao kernel em curso, com a rotina chamada quando a instrução é a de
  um import pela IAT; senão a cadeia de RBP do próprio kernel), os
  registradores inteiros do CONTEXT e até 16 quadros desenrolados pela
  .pdata de cada imagem (`rtl/frame_walk.rs`, o mesmo desenrolamento do
  `[crash]` de modo usuário) e, nas funções do kernel, pelos frame pointers.
  Cada endereço sai como módulo+deslocamento pela PsLoadedModuleList (que
  também traz as imagens de sessão) e com o export mais próximo. O bloco não
  aloca, não espera trava e só lê páginas presentes da metade de sistema
  mapeadas com cache, então serve em qualquer IRQL; uma página das imagens
  de sessão que a raiz corrente não mapeia sai pela raiz de um processo da
  sessão. A linha `(fim: ...)` diz onde e por que a pilha acabou. A exceção
  de kernel que não chega ao despacho (`*** EXCECAO DE KERNEL`) ganha os
  mesmos quadros.
  O autoteste `ntos/test/kernel_crash_trace.rs` (fase 6) confere a descrição
  de um trampolim de export, a decodificação das chamadas, a cadeia de RBP e
  as recusas do leitor. A análise sai do próprio log, sem o alvo
  (`tools/opennt-kd/src/crash`, `cargo xtask crash [SERIAL.LOG]`): o código
  e o sentido dos parâmetros no 19041, onde parou, o módulo culpado (o do
  ponto de partida, ou o primeiro quadro fora do kernel e da HAL), o
  componente provável e a pilha do `[kcrash]` com os públicos dos PDBs e,
  no `ntoskrnl.exe` (o kernel do OpenNT), com os símbolos do `kernel.elf`;
  as imagens vêm das linhas `[pe] base=` do boot. Dos dados secundários sai
  o WdLog do dxgkrnl (os anéis de asserções, erros, avisos, eventos e
  rastro, com o status de cada entrada) e, por sequência, as apresentações
  (`DdiPresentDisplayOnly`) e as mudanças de VidPn da primeira tela. O
  test-boot que falha com uma parada imprime o mesmo resumo, e o
  `test-boot --manual-crash` manda a parada manual pelo monitor do QEMU no
  fim da execução, para que um boot que não para também traga os dados
  secundários. O `cargo xtask logsum SERIAL.LOG` resume o log inteiro:
  marcadores, fim, memória, a árvore de processos com o fim de cada um, as
  falhas de syscall por processo, as syscalls sem implementação e os laços.
- **Pedidos térmicos** (`po/thermal.rs`, `po/reason_context.rs`): a
  extensão de resfriamento de cada alvo recebe a
  GUID_THERMAL_COOLING_INTERFACE por um IRP_MN_QUERY_INTERFACE síncrono ao
  alvo; o agregado dos pedidos (menor percentual, OU dos ativos) chama
  PassiveCooling/ActiveCooling do driver só quando muda, sem trava, e o
  último pedido devolve a interface. A extensão fica num registro por
  dispositivo (no NT, na DOPE do alvo).
- **Pedidos de energia de modo usuário** (`po/power_request.rs`,
  `po/reason_context.rs`): o NtPowerInformation 43 (PowerRequestCreate) e 72
  (PlmPowerRequestCreate) capturam o COUNTED_REASON_CONTEXT com sondas de
  modo usuário e devolvem um handle sem acesso de um objeto PowerRequest de
  dono UserMode; o 44 (PowerRequestAction) liga e desliga o tipo interno pelo
  handle; o fechamento do último handle (PopClosePowerRequestObject) desconta
  os tipos ligados. O NtSetThreadExecutionState guarda o pedido legado da
  thread em ETHREAD.LegacyPowerObject (o PspExitThread o solta) e devolve as
  flags anteriores com ES_CONTINUOUS; sem ES_CONTINUOUS, só reinicia a
  ociosidade e avisa o win32k da presença no console.
- **Callouts de energia ao win32k** (`po/win32_callout.rs`): o
  PopInvokeWin32Callout manda os callouts de evento (tipo 3), estado (4) e
  informação (5) pelo despachante do win32k, por sessão; a troca de hora
  (`po/time_change.rs`) termina no evento PsW32SystemTime (o WM_TIMECHANGE),
  o NtSetThreadExecutionState(ES_DISPLAY_REQUIRED) na presença do usuário no
  console, e o NtPowerInformation 28 no PoPowerOffMonitor (bloqueio da troca
  de console, tarefas e tela apagada). O evento de desligamento
  (PopDispatchShutdownEvent) espera o PopExecutePowerAction, que o OpenNT
  ainda não tem.
- **Ações de energia** (`po/power_action.rs`): ZwInitiatePowerAction valida
  como o NtInitiatePowerAction; sem a política de energia
  (PopExecutePowerAction) as ações reais devolvem STATUS_NOT_SUPPORTED, e
  o PoShutdownBugCheck cai no bugcheck pedido. PoSetHiberRange só aceita
  um mapa fechado: o OpenNT não hiberna.
- **Informações de energia** (`po/power_information.rs`,
  `po/power_setting.rs`): o NtPowerInformation de modo usuário segue o
  19041 (níveis só de kernel recusados, privilégio para entrada fora da
  lista sem privilégio, entrada capturada, saída sondada e o fim comum de
  cópia); os níveis 4, 5, 29, 58, 59, 66 e 75 têm o mesmo corpo de modo
  kernel e de usuário; só de modo usuário, os níveis 14 e 15 (zero sem
  transição de sono), 16 (SystemExecutionState pelos pedidos ligados), 28
  (contexto administrador), 64, 65, 94 (o gravador black box com o buffer
  sondado e a categoria SCM só para processo protegido) e 95. Os níveis 61 (SessionRITState) e 62
  (SessionConnectNotification), só de modo kernel, são a entrada e a
  conexão da sessão que o win32kbase informa (`po/user_presence.rs`): a
  conexão do console liga GUID_SESSION_DISPLAY_STATUS da sessão e a torna
  a sessão do console; a conexão e a entrada ativa deixam a sessão
  PowerUserPresent, a entrada passiva e a desconexão PowerUserInactive, em
  GUID_SESSION_USER_PRESENCE da sessão; GUID_GLOBAL_USER_PRESENCE é
  PowerUserPresent com alguma sessão presente e muda junto com
  WNF_PO_SLEEP_STUDY_USER_PRESENCE_CHANGED. Os timeouts de entrada e de
  tela que os dois devolvem ficam zero, porque os callbacks internos do Po
  que os gravam não são registrados. O nível 4 é o PopCapabilities de um desktop S0/S5
  (0x4c bytes, só o botão de energia, o S5, o FullWake e o DiskSpinDown), o
  5 é o estado composto sem bateria (AcOnLine) e o 29 (SystemVideoState,
  que o CProcessStateManager do LogonUI pede antes de subir o servidor RPC)
  são os 4 bytes do PopConsoleDisplayState (`po/display_state.rs`). Esse
  estado nasce ligado no PoInitSystem e muda pelo 42 (SessionDisplayState,
  só de modo kernel), o aviso de tela do win32kbase: entrada de 0x10 bytes
  sem saída; com os BOOLEANs de +0xC e +0xD, o GUID_SESSION_DISPLAY_STATUS
  da sessão e o PopUpdateConsoleDisplayState (GUID_CONSOLE_DISPLAY_STATE,
  GUID_MONITOR_POWER_ON e WNF_UBPM_CONSOLE_MONITOR, só quando o estado
  muda); com +0xC e +0xE, WNF_PO_PRIMARY_DISPLAY_VISIBLE_STATE. As
  configurações de power setting nascem do PopSetPowerSettingValue (no
  boot, o PopInitilizeAcDcSettings grava GUID_ACDC_POWER_SOURCE): o nível 58 cria
  no primeiro pedido o nome WNF temporário de escopo de máquina da
  configuração (ou o nome global, sem GUID; GUID desconhecido dá
  STATUS_NOT_FOUND) e o 59 serializa os valores AC, DC e Hot com os
  carimbos de mudança. A entrega das mudanças segue o 19041
  (`po/policy_worker.rs`): da fase 3 do PoInitSystem em diante, o
  PopSetNotificationWork põe o worker de política (um work item no
  processo System) a rodar o PopPolicyWorkerNotify, que chama o
  PopDispatchPowerSettingCallbacks (bit 0x20) e o PopDispatchNotifications
  (0x80) e espera 10 ms entre as voltas. Os registros do
  PoRegisterPowerSettingCallback são blocos 'PSet' (o handle) na lista da
  configuração do GUID ou à espera dela; o registro pede a entrega, então
  o callback recebe o valor corrente (o callback inicial) e depois cada
  troca do slot da fonte corrente, com o PopSettingLock solto durante a
  chamada; um setting de sessão é recusado. O
  PoUnregisterPowerSettingCallback de dentro do próprio callback fica para
  a volta; o de outra thread espera o callback voltar. O nome WNF criado
  pelo nível 58 recebe a publicação do valor corrente e de cada troca (os
  registros do PopMarshalSettingValues), que é o que o
  RegisterPowerSettingNotification do user32 e o powrprof assinam (o
  LogonUI pede GUID_CONSOLE_DISPLAY_STATE, GUID_LOW_POWER_EPOCH,
  GUID_SESSION_USER_PRESENCE, GUID_LIDSWITCH_STATE_CHANGE e
  GUID_SESSION_DISPLAY_STATUS; um GUID ainda sem configuração fica no nome
  global até ela nascer); uma configuração nova é avisada no nome global.
  Os valores do esquema de energia chegam do serviço Power pelo
  `\PowerPort` (a mensagem 4, PopSetNewPolicyValue: GUID_ACTIVE_POWERSCHEME
  e cada setting do esquema ativo, AC e DC; os settings de sessão são
  ignorados; no subgrupo do processador só o perfil nulo) e passam pelo
  PopValidatePowerSettingData (mínimos dos timeouts de disco, standby e
  hibernação). O PowerInformationInternal 0x1F e 0x20 (o
  RtlGet/SetSystemBootStatus do ntdll) lê e grava o boot status data (`po/boot_status.rs`): os itens
  capturados e sondados, o arquivo `\SystemRoot\bootstat.dat` aberto pelo
  ZwOpenFile (ou o `OsBootstatPath` de `Control`), o acesso do chamador ao
  descritor dele, os campos do RtlpBootStatusFields pelo cache, o checksum
  ajustado no Set e o campo gravado no black box. O volume não tem o
  arquivo, então o pedido devolve o status da abertura. O nível 87 de modo
  kernel passa pelo mesmo PopPowerInformationInternal (sem captura), e os
  tipos internos só de kernel recusam o modo usuário com
  STATUS_ACCESS_DENIED. O win32kbase usa três: o SessionPowerState (0x13,
  0x14 bytes; com o BOOLEAN de console, o GUID_SESSION_DISPLAY_STATUS da
  sessão e o PopUpdateConsoleDisplayState com o On), o InputControllerState
  (0x1C, o ULONG em GUID_ADAPTIVE_INPUT_CONTROLLER_STATE) e o SetWatchdog
  (0x15, `po/watchdog.rs`): o watchdog de energia é o bloco 'POWD' do
  PopSetWatchdog, criado com um watchdog NULL e saída, armado com um prazo
  em ms (timer, DPC e item de trabalho na DelayedWorkQueue) e desarmado com
  prazo 0 ou apagado; vencido, o worker anexa a sessão dos parâmetros e
  chama o callback deles ou o KeBugCheckEx com o código (o win32kbase usa
  WIN32K_POWER_WATCHDOG_TIMEOUT, 0x19C, cujo estágio vai ao boot status
  data).
- **Power Dependency Coordinator** (`po/pdc.rs`, `po/processor_power.rs`):
  o pdc.sys real é carregado como na instalação (serviço `pdc`, início de
  boot no grupo Boot Bus Extender, `cm/service/inbox_drivers.rs`). O kernel
  só faz a parte dele: o NtPowerInformation 67 (só de modo kernel; entrada
  de 0xB8 bytes e saída nula ou de 0xA0, senão STATUS_INVALID_PARAMETER)
  com o tipo 0, o PopPdcRegister (os 22 ponteiros do pdc.sys no
  PoPdcCallbacks e as 20 rotinas PdcPo* na saída, na ordem da tabela do
  19041, cada uma um stub de `hal/amd64/routine_stubs.rs`), e o tipo 1, o
  registro de cliente de kernel pelo PoPdcCallbacks+0x20 (antes do
  registro, STATUS_NOT_IMPLEMENTED). Com isso o pdc.sys cria a `\PdcPort`,
  o UMPDC.dll do DcomLaunch conecta, o HampManagerAllocateState do
  PsmServiceExtHost.dll registra o cliente de ativação e os servidores RPC
  do HAM sobem (o Lifetime Manager do sihost precisa deles). Os perfis de
  desempenho do PPM que o pdc.sys registra (PpmRegisterProfiles: até 0x1F
  perfis de 0x15B0 bytes com nome, índice, GUID e o BOOLEAN da entrada) e
  aplica (PpmApplyProfile: o perfil corrente e o bit de aplicado) ficam
  guardados. Lacunas reais, cada uma com uma linha `[po]` na primeira
  chamada: a política de desempenho do processador e o PpmDefaultProfile
  (os perfis não mudam nada); a ação de energia (PopExecutePowerAction); o
  motor de políticas que refaz as políticas quando um botão aparece; a
  gravação da transição de energia no bootstat.dat; o agregador de energia
  e a contabilidade do connected standby (fases do PDC, saída do CS, DRIPS,
  resiliência de rede); a coalescência profunda de E/S; o Sleep Study e o
  log de pedidos de energia. O autoteste da fase 6
  (`test/power_io_support.rs`) confere o nível 67: as validações, o registro
  com um PDC sintético (quando o pdc.sys não está carregado), o cliente de
  kernel e as rotinas da tabela, os perfis do PPM inclusive; o [[teste]]
  `sihost` confere que o pdc.sys criou a `\PdcPort`.
- **Desligamento e reinício** (`po/shutdown.rs`, `io/shutdown.rs`,
  `ex/shutdown.rs`, `hal/firmware_return.rs`): NtShutdownSystem e o
  NtSetSystemPowerState das ações de desligamento, de modo kernel e de
  usuário (SeShutdownPrivilege habilitado), seguem o PopGracefulShutdown do
  19041: só com o PoCleanShutdownFlags de `Session Manager\Kernel`
  (CmControlVector, 0 no boot comum) o PopShutdownEvent é sinalizado e as
  threads do PoRequestShutdownEvent são esperadas (a thread de entrada da
  sessão 0 do win32kfull nunca termina sem ele); ExShutdownSystem(0) (o
  ShutdownTime em Control\Windows), IoShutdownSystem(0) (IRP_MJ_SHUTDOWN
  síncrono no topo da pilha de cada IoRegisterShutdownNotification, da
  cabeça para a cauda), CmShutdownSystem (as hives no disco),
  MmShutdownSystem(0) (`mm/shutdown.rs`: as páginas alteradas de toda
  seção de dados de arquivo com vista, o MiFlushAllFilesystemPages),
  IoShutdownSystem(1) (os file systems das filas de disco, CD-ROM e fita,
  sob o IopDatabaseResource que não é mais solto, o NTFS do volume de boot,
  que descarrega o disco e passa a recusar criação, escrita, metadado e
  paginação com STATUS_TOO_LATE como o NtfsShutdownVolume, e a fila de
  última chance), CcWaitForCurrentLazyWriterActivity e o
  PopShutdownSystem, que vai ao HalReturnToFirmware: S5 pelo PM1x_CNT com
  o HalpShutdownContext do HaliAcpiMachineStateInit (sem o acpi.sys, do
  `\_S5_` da DSDT) ou o reinício (CMOS 0x0F, 0x472, RESET_REG, 8042). Um
  segundo pedido espera em KernelMode, sem prazo, o PopTransitionLock que o
  primeiro nunca solta (a CPU dele segue rodando). Os pontos de controle da
  transição (`po/transition_checkpoint.rs`, o PopTransitionCheckpoint e o
  PowerInformationInternal 0x1b do wininit e do csrss) são registrados. A
  política DontPowerOffAfterShutdown faz o ShutdownNoReboot parar sem
  desligar. Os passos de componentes que o OpenNT não tem (Tm, Etw, os
  IRPs S5 aos dispositivos) ficam de fora. O shell tem `shutdown` e
  `reboot`; o `--shutdown-test` cobre o caminho inteiro com o ntfs.sys real
  (testes `shutdown` e `reboot`) e, com `cadeia`, o desligamento da cadeia
  real pelo shutdown.exe e o boot seguinte do disco gravado (teste
  `desligamento-cadeia`).
- **Dependências entre dispositivos** (`io/dependency.rs`): o grafo das
  Pip* (nós 'PnpS' em DEVOBJ_EXTENSION.DependencyNode, arestas com os
  pedidos por dispositivo ou por nome de ligação, ids de ligação). Ficam de
  fora a ancestralidade dos devnodes na validação de uma aresta, a fila de
  relações de energia, a liberação do início dos dependentes e a
  notificação de propriedade, que dependem do PnP.
- **Ejeção, remoção para reset e recursos legados**
  (`io/device_removal.rs`, `io/legacy_resources.rs`): as validações, os
  blocos de contexto e o worker do IoRequestDeviceEject(Ex) e do
  IoRequestDeviceRemovalForReset são os do ntoskrnl; o PnP do OpenNT ainda
  não processa eventos de remoção ou ejeção de dispositivo-alvo, e o
  pedido conclui com STATUS_TOO_LATE (a recusa do PnpSetTargetDeviceRemove
  quando a máquina de eventos não aceita o evento). O IoAssignResources
  libera e valida como o original, mas sem árbitros de recursos nenhuma
  configuração existe: STATUS_RETRY.
  Testes: `ntos/test/rtl_ranges_resources.rs`, `ntos/test/platform_support.rs`,
  `ntos/test/power_io_support.rs` e `ntos/test/device_removal.rs`.
- **Volumes do kernel nos seus dispositivos** (`drivers/fs/volume_device.rs`):
  como no NT, um volume é alcançado pelo seu dispositivo e por links, não
  por um nome na raiz. O disco em memória e o leitor NTFS do segundo disco
  IDE ficam em `\Device\KernelVolume0` e `\Device\KernelVolume1`
  (DEVICE_OBJECTs FILE_DEVICE_DISK com VPB e DeviceLock), montados pelo
  file system embutido do kernel: o VPB aponta um dispositivo de volume
  FILE_DEVICE_DISK_FILE_SYSTEM (DRIVER_OBJECT `\FileSystem\KernelVolume`) e o
  IopMountInitializeVpb o marca montado. `\FS` e `\??\C:` levam ao
  primeiro, `\??\D:` e `\SystemRoot` (`...\Windows`) ao segundo; no boot do
  smss o `\??\C:` também leva ao segundo, o volume do sistema, que é o C:
  dos caminhos do modo usuário (o win32k abre o `\??\C:\WINDOWS\FONTS\X.TTF`
  que o AddFontResource lhe passa); o nó do
  dispositivo entrega o resto do nome ao volume (`object_manager::mount_device`),
  e os nomes das fontes de imagem saem do dispositivo (`ntfs::nt_path`).
  Todo FILE_OBJECT aberto num desses volumes (ZwCreateFile do kernel, as
  fontes de imagem e os arquivos de usuário) nasce como o do IopParseDevice:
  DeviceObject = o dispositivo real, Vpb = o VPB (uma referência até a
  destruição) e FileName = o caminho no volume. O
  IoGetBaseFileSystemDeviceObject e o IoGetRelatedDeviceObject chegam ao
  dispositivo de volume (o FltMgr e a CI partem deles); o file system
  embutido não tem pilha de IRP, então o I/O Manager responde no lugar as
  operações desses arquivos (`information::related_device` dá 0 para eles)
  e um IRP mandado ao dispositivo de volume termina com
  STATUS_INVALID_DEVICE_REQUEST. As exceções (`information::request_device`,
  `volume_device::serves`) são o IRP_MJ_LOCK_CONTROL do
  NtLockFile/NtUnlockFile, que o dispositivo de volume entrega às travas do
  stream (`drivers/fs/volume_streams.rs`, o NtfsCommonLockControl sobre o
  FsRtlProcessFileLock): a leitura e a escrita de modo usuário conferem
  essas travas (STATUS_FILE_LOCK_CONFLICT) e o cleanup e o fechamento do
  último handle de um processo soltam as dele; e o IRP_MN_NOTIFY_CHANGE_DIRECTORY
  do NtNotifyChangeDirectoryFile(Ex), que vai à lista de notificação do
  diretório (o NtfsNotifyChangeDirectory sobre o FsRtl Lite, com o
  FsRtlCancelNotify): a criação, a remoção e a renomeação do volume relatam
  as mudanças a cada diretório acima com lista (o NtfsReportDirNotify), a
  escrita relata FILE_ACTION_MODIFIED no cleanup do arquivo, um diretório
  removido conclui os pedidos com STATUS_DELETE_PENDING e o NtCancelIoFileEx
  de um handle de arquivo cancela os IRPs que o I/O Manager acompanha para o
  FILE_OBJECT (teste `volume_notify_locks` na fase 7). Os serviços de modo usuário NtFlushBuffersFile(Ex) (acesso de
  escrita ou de acréscimo; o IRP_MJ_FLUSH_BUFFERS com o minor dos flags num
  arquivo de driver), NtFlushVirtualMemory (a vista de arquivo gravada de
  volta: `ps/user/sections.rs::flush` junta as páginas alteradas vizinhas,
  até 16 por escrita, do primeiro ao último byte alterado, com o conteúdo
  atual do arquivo nos bytes que a vista não mudou), NtQueryEaFile/NtSetEaFile (sondas, a lista FILE_GET_EA_INFORMATION
  conferida, FILE_READ_EA/FILE_WRITE_EA, e as EAs `$KERNEL.` só do modo
  kernel), NtCancelSynchronousIoFile (as requisições síncronas da thread
  canceladas, ou STATUS_NOT_FOUND) e NtDeleteFile (a abertura DeleteOnly com
  FILE_DELETE_ON_CLOSE) seguem o 19041 (teste `user_desktop_services` na
  fase 7). O NtReadFileScatter e o NtWriteFileGather (`io/file/scatter_gather.rs`)
  fazem as checagens do 19041 na ordem de cada serviço (arquivo
  FO_NO_INTERMEDIATE_BUFFERING e assíncrono, dispositivo de file system sem
  DO_BUFFERED_IO, a lista de páginas inteiras alinhada e copiada, o setor do
  dispositivo, o ByteOffset obrigatório); num arquivo de driver o IRP leva o
  MDL das páginas da lista (MmProbeAndLockSelectedPages, `mm/mdl.rs`), e num
  arquivo do volume os bytes vão entre o arquivo e as páginas ali mesmo
  (`ps/user/file_io::segment_transfer`), com a conclusão de um pedido
  assíncrono atendido na hora: o IO_STATUS_BLOCK, o evento (ou o do
  FILE_OBJECT), a APC de usuário ou o pacote da porta de conclusão (teste
  `user_extended_services` na fase 7). O NtSetVolumeInformationFile
  (`io/file/irp_service.rs::set_volume_information`, o 0x76c860) confere a
  classe, o tamanho, as sondas, o acesso e o VolumeLabelLength e manda o
  IRP_MJ_SET_VOLUME_INFORMATION, com o GUID_IO_VOLUME_CHANGE ao PDO depois
  do sucesso; um arquivo do file system embutido que não é a abertura do
  volume recebe STATUS_ACCESS_DENIED, como do NTFS. Na abertura do volume, o
  file system embutido grava o rótulo no $VOLUME_NAME e no VPB e o ObjectId
  do volume no $OBJECT_ID do $Volume e no $O do `$Extend/$ObjId`
  (`ntfs_write.rs`, lido pelo FileFsObjectIdInformation); sem a tabela de
  cotas aberta, o FileFsControlInformation é STATUS_INVALID_PARAMETER. Um arquivo do volume aberto pelo modo usuário não tem o backing do
  ZwCreateFile: as seções graváveis (`mm/section/file.rs`) e as EAs
  (`io/kernel_ea.rs`) usam o volume e o caminho da fonte do FILE_OBJECT. O volume de boot guarda o conteúdo de
  `\Windows` na raiz (os programas de System32, `Fonts`, os temas...), que o
  modo usuário abre pelos aliases de `volume_files::nt_path_to_volume_path`;
  a abertura do kernel por `\SystemRoot\X` ou `\??\C:\Windows\X` que não
  existe literalmente em `/Windows` vai ao mesmo arquivo da raiz
  (`volume_files::install_alias`, o mesmo para `System32` e
  `Globalization\Sorting`), e os drivers e catálogos que existem em
  `/Windows/System32` ficam onde estão: sem isso o win32k não abria nenhuma
  fonte (`\SystemRoot\Fonts\VGASYS.FON`) e a sessão ficava sem fonte
  padrão. Teste: `kernel_volume_devices` na fase 6.
  O dispositivo real responde a interface MOUNTDEV de um volume básico do
  volmgr.sys (`volume_device::mount_control`: o nome, o identificador único
  `DMIO:ID:` com o GUID estável, nenhuma letra sugerida), e o
  IoGetDeviceObjectPointer do nome do volume faz a abertura direta (o
  OpenDevice do mountmgr.sys exige FileName vazio). No boot do smss,
  `io/boot_partition.rs` faz o IopMarkBootPartition e o
  IopAssignBootDriveLetter do 19041: marca o dispositivo
  DO_SYSTEM_BOOT_PARTITION, tira o `\GLOBAL??\C:` provisório da fase 1,
  entrega o volume ao mountmgr.sys real pelo
  IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION e pede a letra com o
  IOCTL_MOUNTMGR_BOOT_DL_ASSIGNMENT (marcador MOUNTMGR_BOOT_VOLUME_OK); se o
  mountmgr.sys não cria o C:, o link provisório volta. A
  FILE_NORMALIZED_NAME_INFORMATION (48) devolve o caminho com os nomes longos
  gravados (`Ntfs::long_name`). Teste: `volume_mountdev` na fase 7.
- **Arquivos dos volumes do kernel** (`io/file/lifetime.rs`): os volumes
  internos (o disco em memória e o NTFS) não têm driver de file
  system, então o registro de vida faz o papel do FCB: um estado por arquivo
  com o SHARE_ACCESS, a exclusão pendente e o SECTION_OBJECT_POINTERS do
  arquivo. Todo FILE_OBJECT aberto num desses volumes (ZwCreateFile do
  kernel ou NtCreateFile de usuário) publica esse bloco em
  FILE_OBJECT.SectionObjectPointer, como o IRP_MJ_CREATE de um file system;
  as aberturas do mesmo arquivo dividem o bloco, que vive enquanto houver
  FILE_OBJECT ou SECTION no arquivo. As seções do OpenNT ainda não publicam
  CONTROL_AREA nele (os três ponteiros ficam NULL), mas código que lê
  FileObject->SectionObjectPointer->ImageSectionObject sem conferir, como a
  ci.dll ao registrar uma validação recusada, encontra memória válida.
  Teste: `zw_kernel_files` na fase 6.
- **Cópia de arquivo (NtCopyFileChunk)** (`io/file/copy_chunk.rs`,
  `irp_service::DriverFile`): o caminho de dados do CopyFile do kernelbase
  (BaseCopyStream não tem caminho por ReadFile). Como o NtCopyFileChunk do
  19041, a origem decide o modo: síncrona devolve o status da escrita, com
  o IO_STATUS_BLOCK gravado e o evento sinalizado; assíncrona devolve
  STATUS_PENDING com os dois já concluídos. Os parâmetros da escrita são
  validados antes da leitura (DestOffset obrigatório e não negativo, salvo
  FILE_WRITE_TO_END_OF_FILE; só FILE_APPEND_DATA escreve no fim), e uma
  leitura que falha sem ficar pendente (fim do arquivo) volta direto, sem
  tocar no IO_STATUS_BLOCK. Num destino sem buffer intermediário a escrita
  sobe ao setor, com o resto zerado. Cada lado é um arquivo do volume do
  kernel ou um arquivo de driver, lido e escrito por IRP de modo kernel
  sobre o buffer do pool. Os arquivos do volume respondem também
  FileHardLinkInformation (46, os $FILE_NAME fora do namespace só DOS) e
  FileStorageReserveIdInformation (74: o volume não tem áreas de reserva,
  então o id é 0 e mudar para outro dá STATUS_STORAGE_RESERVE_DOES_NOT_EXIST).
  Teste: `user_copy_chunk` na fase 7.
- **Reparse points do volume de boot** (`drivers/fs/ntfs_reparse.rs`,
  `io/reparse.rs`): o NTFS do kernel guarda o reparse point como o
  ntfs.sys, no formato do disco: o atributo $REPARSE_POINT com o buffer do
  FSCTL, a FILE_ATTRIBUTE_REPARSE_POINT no $STANDARD_INFORMATION e nas
  informações duplicadas da entrada do diretório pai (com a tag no lugar
  do tamanho de EA) e a entrada (tag, referência) no índice $R do
  `$Extend\$Reparse` (`ntfs_write::store_reparse`; a remoção do arquivo
  tira a entrada). Os FSCTL_SET/GET/DELETE_REPARSE_POINT chegam ao volume
  pelo NtFsControlFile de usuário num arquivo do volume, pelo
  ZwFsControlFile/NtFsControlFile de kernel e pelo FsRtlKernelFsControlFile,
  com as checagens do NtfsSetReparsePoint/NtfsGetReparsePoint/
  NtfsDeleteReparsePoint (acesso, buffer, tag, diretório vazio, o
  SeCreateSymbolicLinkPrivilege do SYMLINK). Na abertura, o volume devolve
  o reparse point do caminho (intermediário, ou o último sem
  FILE_OPEN_REPARSE_POINT) e o I/O Manager faz o IopGraftName (junção,
  link absoluto e link relativo resolvido no nome aberto através das
  junções), a conferência do dispositivo alvo e a política SymlinkEvaluation
  do `Control\FileSystem` (semeada com os valores de uma instalação nova);
  a busca recomeça na raiz (`ps/user/files.rs::open_by_name` no modo
  usuário, `io/file/zw.rs` no kernel) até as 0x40 voltas do
  ObpLookupObjectName, que também limitam os links do namespace. O
  NtQueryAttributesFile segue os intermediários e não o último; a
  FileAttributeTagInformation e as listagens dão a tag. O volume informa
  FILE_SUPPORTS_REPARSE_POINTS. Teste: `reparse_points` na fase 7.
- **Segurança dos arquivos do volume de boot** (`drivers/fs/ntfs_security.rs`):
  o NTFS do kernel guarda o descritor de cada arquivo como o ntfs.sys, no
  $Secure: o SecurityId do $STANDARD_INFORMATION é a chave do $SII, o $SDH
  acha um descritor igual pelo hash e o $SDS guarda as entradas alinhadas a
  16 com a cópia 0x40000 adiante (`ntfs_write::security_id_for`; os índices
  de visão usam a mesma B-tree do $I30). Um arquivo novo recebe o descritor
  do SeAssignSecurityEx (herança do pai, o descritor dos OBJECT_ATTRIBUTES e
  o token de quem cria; em modo usuário, as checagens de dono e de SACL),
  tanto no NtCreateFile quanto no ZwCreateFile; o FILE_SUPERSEDE e o
  FILE_OVERWRITE mantêm o SecurityId. O NtQuerySecurityObject devolve o
  descritor guardado e o NtSetSecurityObject troca as partes pedidas com
  AutoInheritFlags 0 (`ntfs_security::modify`). Um volume sem segurança
  continua com o descritor de World e o sucesso sem mudança do
  IopGetSetSecurityObject. O volume informa FILE_PERSISTENT_ACLS. As
  checagens do NTFS (`ntfs_security::check`, `check_traverse`,
  `check_create`: o NtfsAccessCheck com a concessão pelo pai, o
  FILE_TRAVERSE sem SeChangeNotifyPrivilege e o FILE_ADD_FILE do pai) e o
  contexto do IopParseDevice (`io/parse.rs::volume_open_security`: o
  token, a regra do nível de impersonação e o
  IopCheckBackupRestorePrivilege) rodam no NtCreateFile, no
  NtQueryAttributesFile, no destino de um rename, no ZwCreateFile com
  OBJ_FORCE_ACCESS_CHECK e na abertura do executável do
  NtCreateUserProcess, mas por enquanto só registram a recusa
  (`[filesec] negaria`); a abertura segue com o acesso pedido. Teste:
  `file_security` na fase 7.
- **Tamanho válido dos arquivos do volume de boot** (`drivers/fs/ntfs.rs`,
  `ntfs_write.rs::mutate_data`): como o ntfs.sys, o NTFS do kernel não grava
  zeros nos clusters que aloca. O $DATA não residente guarda o
  ValidDataLength no tamanho inicializado (+56): a extensão (SetEndOfFile,
  AllocationSize) só muda as runs e os tamanhos, a leitura acima do
  ValidDataLength dá zeros sem ler os clusters, uma escrita acima dele zera
  só o vão até ela e o leva ao fim dela, e o corte o traz ao tamanho novo. A
  E/S de paginação dos arquivos de paginação lê os clusters crus (o
  MiCreatePagingFile do 19041 só põe o EndOfFile, e o Mm só lê o que
  gravou). Antes, os 448 MB do `D:\pagefile.sys` e do `C:\swapfile.sys`
  eram gravados com zeros em todo boot do smss (de 5 a 17 s com a thread do
  smss parada). Teste: `ntfs_writer` na fase 4.
- **Transações do NTFS do volume de boot** (`drivers/fs/ntfs_write.rs`): o
  writer guarda uma cópia só do $Bitmap e do $BITMAP do $MFT, os do último
  commit. Uma transação guarda a cópia de cada setor desses bitmaps que ela
  muda; as leituras dela passam por essas cópias, o commit grava no disco as
  que diferem e só depois do FLUSH as aplica, e um aborto apenas as
  descarta. Nenhuma operação copia o bitmap inteiro (cerca de 300 KB num
  volume de 2,5 M clusters). Teste: `ntfs_writer` na fase 4 (abortos no meio
  da alocação e numa transação aninhada, reserva grande gravada no disco).
- **Escrita no lugar do NTFS do volume de boot**
  (`ntfs_write.rs::mutate_data`): como no NtfsCommonWrite, a escrita que não
  muda tamanho, alocação, residência, atributos nem EAs grava os dados e o
  registro do arquivo, sem o $FILE_NAME duplicado no índice $I30 do pai;
  uma mudança deles reescreve a entrada. Diferença declarada: as horas da
  entrada do índice ficam para a próxima mudança dessas (o 19041 as
  atualiza no cleanup, NtfsUpdateDuplicateInfo); a listagem e o stat leem o
  registro do arquivo, não a entrada. Antes, toda escrita reconstruía o
  índice inteiro do pai (a raiz, para os arquivos do System32), e com o
  writeback das seções de arquivo por trecho de bytes alterados (hoje
  agrupado em até 16 páginas, `ps/user/sections.rs::flush`) o FNTCACHE.DAT
  do win32k segurava a thread do csrss de 30 s a mais de 4 min numa fatia
  só, acima do timeout de controle de 30 s do services.exe. Um intervalo de
  usuário de mais de 2 s vai para a serial (`[sched] intervalo longo`,
  `ps/dispatch_perf.rs`). Teste: `ntfs_writer` na fase 4.
- **Estado por processo**: o que no NT mora no EPROCESS e o OpenNT ainda não
  guarda numa estrutura do NT fica em `ps/user/process_state.rs`, um
  `ProcessState` por EPROCESS (o System inclusive), criado por
  `ps::process::create_process` antes da lista ativa e destruído por
  `terminate_process` depois dela. O VAD do processo já mora ali. Estado novo
  de processo entra ali, não num global de `ps/user/state.rs`.
- **Handles por processo**: a tabela de handles de usuário mora no
  `ProcessState` (`handles`), e a linha nativa de cada handle vai para a
  HANDLE_TABLE do mesmo processo (EPROCESS.ObjectTable). As operações de
  `state.rs` sem processo explícito (`alloc_user_handle`, `get_user_handle`,
  `close_user_handle`...) e a resolução do NtClose, do
  ObReferenceObjectByHandle e do NtQueryObject agem sobre a tabela do
  processo corrente, `KTHREAD.ApcState.Process`, que segue o attach como no
  NT. Handles de kernel (OBJ_KERNEL_HANDLE, prefixo 0xFFFFFFFF8...) ficam na
  tabela do System e valem em qualquer processo, só em KernelMode. Cada
  tabela numera os próprios handles (`ob/handle_ids.rs`, `Numbers`), como o
  ExpAllocateHandleTableEntry de uma tabela sem StrictFIFO: o primeiro
  handle é 4, os valores são múltiplos de 4 fora da entrada 0 de cada folha,
  o valor fechado é o próximo a sair (LIFO), e dois processos repetem os
  mesmos valores; a herança põe no filho o valor do pai. Os provedores que
  acham os registros só pelo valor (o Object Manager, os arquivos do zw e o
  registro, com os handles de kernel deles) tiram valores de um espaço
  global a partir de 0x1004, reaproveitados do mais antigo ao mais novo.
  Diferença declarada: um valor vivo num desses provedores não sai para
  nenhuma tabela de usuário, e um vivo numa tabela de usuário não sai para
  eles, então um valor nunca aponta dois donos no processo corrente. No NT
  todo handle de um processo mora na tabela dele, sem essa disjunção. No
  término, a drenagem da HANDLE_TABLE nativa fecha cada handle pela tabela
  do processo dono, e `process_state::destroy`
  fecha o que sobrou (handles sem linha nativa). Teste:
  `ntos/test/multiprocess/handles.rs`.
- **OBJECT_HEADER e rotinas de tipo** (`ob/object_header.rs`,
  `ob/object_create.rs`, `ob/type_procedures.rs`, `ob/objects/created.rs`):
  - ObCreateObject captura os OBJECT_ATTRIBUTES num
    OBJECT_CREATE_INFORMATION e aloca, no pool do tipo (TypeInfo.PoolType,
    tag = OBJECT_TYPE.Key), os cabeçalhos opcionais na ordem do NT
    (preenchimento 0x80, EXTENDED 0x40, AUDIT 0x20, PROCESS 0x10, QUOTA 0x08,
    HANDLE 0x04, NAME 0x02, CREATOR 0x01), o `_OBJECT_HEADER` e o corpo. O
    TypeIndex é `Type->Index ^ ObHeaderCookie ^ (byte 1 do cabeçalho)` sobre
    a ObTypeIndexTable (`object_types`: Type é o índice 2), e
    ObGetObjectType, ObQueryNameInfo (ObpInfoMaskToOffset) e
    OBJECT_TO_OBJECT_HEADER leem o cabeçalho. O registro `LIVE` distingue os
    corpos com cabeçalho; só eles são lidos ali.
  - A vida é a do cabeçalho: PointerCount (ObfReferenceObject,
    ObfDereferenceObject; o último dereference em PASSIVE_LEVEL sem região
    guardada remove na hora, senão vai para a fila do ObpDeferObjectDeletion,
    drenada por um work item em PASSIVE_LEVEL), HandleCount com a contagem
    por processo do HandleInfo (entrada única ou banco 'ObHd'), a cobrança
    de cota no primeiro handle (QuotaInfo ou as cobranças padrão do tipo, no
    ProcessQuotaUsage do EPROCESS) e o nome do NameInfo, que o ObInsertObject
    publica no namespace (a entrada retém o objeto e o NameInfo aponta o
    diretório; o último handle de um objeto temporário o retira).
  - Os handles desses objetos são linhas do Object Manager
    (`open_pointer::insert_with`, com a razão do OB_OPEN_REASON); o dono
    `objects/created.rs` conta cada abertura e fechamento no cabeçalho.
    O ObInsertObject não lê o corpo: um evento do ObCreateObject com
    `*ExEventObjectType` pode ser inserido antes do KeInitializeEvent (o
    BasicRender faz isso). Um handle desses na tabela de um processo de
    usuário vale nas esperas e nos serviços de evento de usuário
    (NtSetEvent, NtResetEvent, NtQueryEvent..., `ps/user/events.rs`), que o
    referenciam como o ObReferenceObjectByHandle(ExEventObjectType,
    UserMode) e agem no mesmo KEVENT.
  - As rotinas do OBJECT_TYPE_INITIALIZER são chamadas nos pontos do NT:
    OpenProcedure na abertura de cada handle (Create, Open, Duplicate),
    CloseProcedure em cada fechamento com as contagens anteriores,
    OkayToCloseProcedure antes do NtClose (FALSE dá
    STATUS_HANDLE_NOT_CLOSABLE), DeleteProcedure na remoção em PASSIVE_LEVEL,
    SecurityProcedure (o SeDefaultObjectMethod quando o tipo não traz uma;
    o descritor do cabeçalho é o que as aberturas do corpo verificam) e
    QueryNameProcedure no ObQueryNameString. Open e Close rodam anexados ao
    processo do handle. A ParseProcedure é chamada pelo ObOpenObjectByName
    (`ob/object_open.rs`) quando a busca chega a um objeto que não é
    diretório e cujo tipo tem a rotina: o RootDirectory (o nome todo é o
    restante) ou o prefixo mais longo de um caminho absoluto que o namespace
    resolve (o restante começa na barra). O nome completo e o restante vão
    numa cópia do kernel terminada em NUL, com o ACCESS_STATE de quem chama
    (ou um local do SeCreateAccessState com o mapeamento do tipo pedido), o
    ParseContext e o SecurityQualityOfService; o objeto devolvido recebe o
    handle e a referência da busca é solta.
  - Os seis tipos Win32 que o executive cria no boot (`ex/win32.rs`:
    WindowStation, Desktop, Composition, RawInputManager, CoreMessaging,
    ActivationObject) têm as rotinas ExpWin32Open/OkayToClose/Close/Delete
    (e a ExpWin32ParseProcedure na WindowStation), rotinas privadas do
    kernel que montam o bloco de parâmetros e chamam o callout do win32k
    pelo PsInvokeWin32Callout no modo de sessão: no processo corrente quando
    ele está na sessão do objeto (o SessionId no primeiro ULONG do corpo),
    senão anexado a um processo da sessão pelo MmAttachSession
    (ExCallSessionCallBack); sem a sessão, STATUS_INVALID_PARAMETER.
  - Ficam fora do modelo de cabeçalho (com donos próprios e contagens no
    registro do dono): processos, threads, tokens, arquivos, dispositivos,
    drivers, seções, chaves, eventos e objetos do despachante, diretórios e
    links do namespace, callbacks e contextos de silo. Dispositivos e
    drivers abrem pelo ObOpenObjectByPointer pelos donos de
    `objects/device.rs` e `objects/driver.rs`.
  - Teste: `ntos/test/object_header.rs` (fase 6 e um processo de teste na
    fase 7).
- **Namespace de objetos do boot, sombras e namespaces privados**
  (`ob/object_manager.rs`, `ob/objects/namespace.rs`,
  `ob/handles/namespace.rs`, `ob/private_namespace.rs`):
  - O kernel publica o que o ntoskrnl 19041 publica antes do primeiro
    processo: `\ObjectTypes` com um objeto do tipo Type por tipo (o
    OBJECT_TYPE como corpo; os tipos criados depois entram pelo
    ObCreateObjectTypeEx), `\GLOBAL??\Global` → `\GLOBAL??`, os sete
    objetos permanentes de `\Callback` do ExpInitializeCallbacks, `\ArcName`
    (vazio: sem ARC_DISK_INFORMATION de um loader, o IopCreateArcNames não
    cria links) e, na fase 1, o tipo KeyedEvent com o
    `\KernelObjects\CritSecOutOfMemoryEvent` (`ex/keyed_event.rs`, que também
    tem os serviços NtCreateKeyedEvent, NtOpenKeyedEvent,
    NtWaitForKeyedEvent e NtReleaseKeyedEvent: os 64 baldes do corpo com a
    KeyedWaitChain, o KeyedWaitValue e o KeyedWaitSemaphore da ETHREAD,
    teste em `ntos/test/keyed_events.rs`), o
    `\KernelObjects\BcdSyncMutant` com o BiBcdMutantDescriptor
    (`bcd/mod.rs`), os eventos do PfInitializeSuperfetch (`pf/mod.rs`) e o
    `\NLS`.
  - O corpo de diretório guarda os campos do OBJECT_DIRECTORY que o OpenNT
    usa: SessionId, Flags, SessionObject, ShadowDirectory e NamespaceEntry.
    O NtCreateDirectoryObjectEx guarda o diretório sombra (Flags 4, e 0x10
    quando quem cria é sandbox) e os bits 8 e 0x20 dos Flags do serviço; a
    busca de abertura (`object_manager::resolve_open_from`/`lookup_open`,
    usada pelo NtOpenDirectoryObject, NtOpenSymbolicLinkObject, NtOpenEvent,
    NtOpenMutant, NtOpenSemaphore e NtOpenIoCompletion) procura na sombra o
    nome que falta, como o ObpGetShadowDirectory; a busca de quem cria não.
  - Os namespaces privados são diretórios sem pai na árvore, achados pela
    fronteira na OBJECT_NAMESPACE_LOOKUPTABLE do silo (37 baldes de
    OBJECT_NAMESPACE_ENTRY, a captura do ObpCaptureBoundaryDescriptor no
    formato da entrada); a criação passa pelo ObpVerifyCreatorAccessCheck,
    a tabela guarda uma referência ao diretório e o último handle ou o
    NtDeletePrivateNamespace o tiram dela. Os serviços que transformam o
    RootDirectory num caminho (`ps/user/registry.rs`, seções, portas de
    conclusão e ALPC) usam `object_manager::anchored_path_of`: dentro de um
    namespace privado, o caminho começa por um componente com o nó e um
    segredo do kernel, que a busca resolve de volta ao diretório; o
    NtQueryObject continua sem nome para esses objetos.
  - Mapas de devices DOS (`ob/device_map.rs`, `se/logon_session.rs`): o
    `\??` não é um objeto. Um nome absoluto `\??\X` (e o próprio `\??`)
    começa no DosDevicesDirectory do DEVICE_MAP de quem procura
    (ObpReferenceDeviceMap): o da sessão de logon do token de impersonação,
    ou o EPROCESS.DeviceMap, preenchido no primeiro uso pelo token primário
    (ObSetCurrentProcessDeviceMap). O token do SYSTEM usa o mapa do
    `\GLOBAL??`, ligado ao System na entrada da fase 1
    (ObpSetSiloDeviceMap); outra sessão de logon recebe o
    `\Sessions\0\DosDevices\<LUID>` na primeira vez (SeGetTokenDeviceMap,
    com o link `Global`; o `\Sessions\0\DosDevices` é do csrss da sessão 0).
    Na busca de abertura, o nome que falta num diretório sem sombra com
    DeviceMap vem do GlobalDosDevicesDirectory (o `\GLOBAL??`); a busca de
    quem cria não sai do diretório. O `\DosDevices` da raiz é um link para
    `\??`. O ProcessDeviceMap consulta (só o processo corrente) e troca
    (ObSetProcessDeviceMap) o mapa; o processo solta o dele no fim e na
    troca do token primário, a sessão de logon no fim dela (os links do
    diretório viram temporários). O DriveMap e o DriveType vêm dos links
    `X:` do diretório na consulta. Teste: `ntos/test/dos_device_maps.rs`
    na fase 6.
  - Fora do modelo: o SessionId do diretório não restringe criações e o
    bit 8 não muda a herança dos descritores. Teste: `namespace`,
    `private_namespaces` e `shadow_directories` na fase 3.
- **Handles e informações entre processos** (`ps/user/handles.rs`):
  - NtDuplicateObject é o ObDuplicateObject: os handles do processo de
    origem e do de destino saem da tabela de quem chama e pedem
    PROCESS_DUP_HANDLE; o handle de origem é procurado na tabela do processo
    de origem (o pseudo-handle de processo é o próprio processo de origem);
    a cópia entra na tabela do destino anexado a ele
    (`state::duplicate_user_handle_in`), com o acesso (DUPLICATE_SAME_ACCESS
    ou um subconjunto do da origem; direitos a mais são negados) e os
    atributos (OBJ_INHERIT, OBJ_PROTECT_CLOSE ou DUPLICATE_SAME_ATTRIBUTES)
    pedidos, e os callbacks de objeto recebem os dois processos;
    DUPLICATE_CLOSE_SOURCE fecha a origem no processo de origem, anexado a
    ele, também quando a duplicação falha ou o destino é nulo.
  - Herança: com `CreateProcessRequest.inherit_handles_from` (o
    PROCESS_CREATE_FLAGS_INHERIT_HANDLES), `create_user_process` chama
    `process_state::inherit_handles` logo depois do `create_process`, como o
    ObInitProcess: cada handle do pai com OBJ_INHERIT entra no filho com o
    MESMO valor, acesso e atributos, sobre a mesma descrição aberta e com a
    linha na ObjectTable do filho, sem callbacks de objeto (só a contagem por
    handle). Os handles que outros provedores publicam na ObjectTable do pai
    (aberturas Zw de modo kernel sem OBJ_KERNEL_HANDLE) não são herdados.
  - NtOpenProcess e NtOpenThread por CLIENT_ID: a mesma captura do NT
    (OBJECT_ATTRIBUTES obrigatório, nome ou CLIENT_ID ausente →
    STATUS_INVALID_PARAMETER_MIX, STATUS_INVALID_CID), de qualquer processo;
    o acesso é concedido pelo SeDebugPrivilege do token efetivo ou pela DACL.
    Processo e thread têm cada um o seu descritor (os dois nascem do DACL
    padrão do token primário do processo; o NtSetSecurityObject troca cada
    um). A OpenProcedure dos dois tipos (`ps/open_procedure.rs`, o
    PspProcessOpen/PspThreadOpen) roda em todo handle novo, de usuário ou de
    kernel, depois dos callbacks: PROCESS_QUERY_INFORMATION (ou
    PROCESS_VM_OPERATION com PROCESS_VM_WRITE) implica
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION implica
    PROCESS_SET_LIMITED_INFORMATION, PROCESS_TERMINATE de UserMode num
    processo DisallowUserTerminate é negado; THREAD_QUERY_INFORMATION,
    THREAD_SET_INFORMATION e THREAD_SUSPEND_RESUME implicam as versões
    limitadas e THREAD_RESUME. Antes disso vem a proteção do alvo: os
    direitos que o RtlProtectedAccess nega pelo signatário do PS_PROTECTION
    dele (sem o de término para o pai) recusam o handle de UserMode quando a
    proteção do processo dono do handle não domina a do alvo
    (RtlTestProtectedAccess; a política de depuração da CI,
    SeCiCallbacks+0xC0, não é consultada e vale FALSE, como num boot sem
    política de Secure Boot).
  - NtQueryInformationProcess(ProcessBasicInformation, ProcessImageFileName)
    lê o EPROCESS do handle (PROCESS_QUERY_LIMITED_INFORMATION): PEB, PID,
    InheritedFromUniqueProcessId, prioridade base e código de saída, ou o
    caminho da imagem do `ProcessState`; NtQueryInformationThread já lia a
    thread do handle (TEB e CLIENT_ID da ETHREAD). A ProcessBasicInformation
    aceita só 0x30 bytes ou os 0x40 da PROCESS_EXTENDED_BASIC_INFORMATION
    (Size e os Flags IsProtectedProcess..IsSubsystemProcess do EPROCESS),
    em modo usuário e em modo kernel (`ps/query_process::basic_information`,
    a forma que o BasicRender consulta); outro comprimento é
    STATUS_INFO_LENGTH_MISMATCH sem ReturnLength.
  - Teste: `ntos/test/multiprocess/cross_handles.rs`.
- **Memória entre processos** (`ps/user/memory.rs`, `mm/copy_virtual.rs`):
  - NtAllocateVirtualMemory(Ex), NtFreeVirtualMemory e
    NtProtectVirtualMemory (PROCESS_VM_OPERATION) e NtQueryVirtualMemory
    (PROCESS_QUERY_LIMITED_INFORMATION; PROCESS_QUERY_INFORMATION nas
    classes 1, 4 e 11 para quem não é administrador nem tem
    SeProfileSingleProcessPrivilege) agem sobre o processo do handle
    (`memory::with_process_handle`, o ObReferenceObjectByHandle em UserMode:
    pseudo-handle, tabela de quem chama, direito ausente →
    STATUS_ACCESS_DENIED, processo retido durante a operação). Os ponteiros
    de quem chama (base, tamanho, proteção anterior, a saída da consulta) são
    lidos e escritos no contexto dele, e o espaço alvo é editado pela raiz
    dele (`Space::root`), sem anexar: o efeito do "captura, anexa, opera,
    desanexa" do NT. NtMapViewOfSection e NtUnmapViewOfSection fazem o mesmo
    (PROCESS_VM_OPERATION; a vista entra no VAD e na raiz do alvo).
  - NtReadVirtualMemory/NtWriteVirtualMemory (PROCESS_VM_READ/
    PROCESS_VM_WRITE) e o export MmCopyVirtualMemory passam por
    `copy_virtual::copy_virtual_memory`: blocos de até 64 KB por um buffer de
    kernel, anexado à origem para ler e ao destino para gravar
    (`process_context::with_process`). Cada lado obedece às PTEs e ao modo
    estrito do espaço anexado; a primeira página inacessível, de qualquer
    lado, encerra com STATUS_PARTIAL_COPY e a contagem exata do que chegou ao
    destino (o prefixo legível do bloco é gravado antes). Tamanho zero é
    sucesso sem olhar o handle; em UserMode, faixas fora da metade de
    usuário dão STATUS_ACCESS_VIOLATION; um processo terminado ou saindo dá
    STATUS_PROCESS_IS_TERMINATING. Os blocos andam para a frente, como no NT.
  - Teste: `ntos/test/multiprocess/cross_memory.rs`.
- **Identidade do processo**: PID, PEB e cookie são os campos do EPROCESS
  corrente (`state::current_process_id`, `state::current_peb`, o
  `EPROCESS.Cookie`); o caminho da imagem, a PEB_LDR_DATA do kernel e os
  exports das imagens mapeadas ficam no `ProcessState`. Um processo de
  usuário é um processo vivo com PEB (`state::is_user_process`); o System e
  os processos do escalonador não têm PEB, como no NT.
- **Ids de cliente**: PIDs e TIDs saem de uma tabela só, `ps/cid.rs` (o papel
  da PspCidTable). `create_process`/`create_kernel_thread` recebem
  `cid::ALLOCATE` para o próximo id livre, ou um id fixo (o System, os
  autotestes); o id fica com o objeto até ele ser recolhido, e um id em uso
  é recusado para outro processo ou thread.
- **Registro do serviço em curso**: o vetor bruto de argumentos e a pilha
  sondada de um serviço de usuário são da thread que o executa
  (`state::SyscallRecord`, por KTHREAD), gravados por
  `ex/system_services.rs` e lidos por `state::service_raw_arguments`.
- **Ciclo de vida por processo**: o que um processo possui volta quando ele
  termina, e só o dele; não há reinício global entre um processo e o
  próximo. As threads de usuário ficam na lista do processo
  (`ProcessState.threads`, com `started` marcando a entrada no despachante) e no
  índice global de `ps/user/threads.rs` (despachante, APCs, busca por id de
  cliente) até serem liberadas. O NtCreateThreadEx com o handle de outro
  processo (PROCESS_CREATE_THREAD; o CtrlRoutine que o csrss manda aos
  processos no desligamento e no logoff) cria a thread anexado ao alvo, como
  o PspCreateThread: TEB, pilha e ETHREAD no processo dele, o PID dele no
  CLIENT_ID e o handle na tabela de quem chamou. Os módulos do loader do
  kernel, com as imagens, ficam em `ProcessState` (a ntdll é do sistema e
  vale em todos).
  O término (`terminate_process`) chama as rotinas de saída de processo, e a
  de `ps/user/files.rs::release_user_resources(process)` libera E/S pendente
  de `device_io`, fábricas de workers, a cópia do callback de
  instrumentação, mutantes, threads, canais de `cm::service::rpc` e picos de
  `system_process_information` do processo; depois `process_state::destroy`
  fecha os handles, devolve o VAD e as imagens dos módulos. Uma thread nunca
  é recolhida enquanto é a corrente, está no meio de um intervalo de
  usuário ou está bloqueada no kernel com o serviço na pilha:
  `threads::release_process` deixa o KTHREAD dela para quando o chamador
  trocar de volta (e o despachante desfizer o serviço) e chamar de novo. Toda falha depois da criação
  de um processo também passa pelo término. Teste:
  `ntos/test/multiprocess/lifecycle.rs`.
- **Recolhimento de threads**: a thread de usuário que sai (o
  NtTerminateThread de outra thread ou dela mesma, ou o PspExitThread no
  próprio contexto) solta na hora a espera, as APCs, o token de
  impersonação, a associação com IOCP e os mutantes, e o objeto thread fica
  sinalizado; o ceifador do despachante
  (`threads::release_execution_resources`) devolve a pilha, a TEB, o
  CONTEXT e a pilha de kernel. A ETHREAD vive enquanto houver handle
  (`ThreadHandleObject`) ou referência (`process::reference_thread`, as
  esperas e associações que retêm o handle), como o objeto do NT: o último
  fechamento tira a thread do índice e o `process::collect_thread` solta o
  registro, o TID e a memória (o PspThreadDelete). Com `--heap-census`, a
  cada 256 threads de usuário que saem vai para a serial o censo de objetos
  (`[heap-census] objetos`): o heap, as threads mortas com handles abertos,
  as ETHREADs registradas, os corpos de despacho por tipo
  (quantos/sem handle/referências), os pacotes de espera por fase e os
  handles do processo por tipo. Teste: `ntos/test/thread_reclaim.rs`.
- **Criação de processos**: um caminho só, `ps/create.rs::
  create_user_process` (o papel do PspCreateProcess/PspAllocateProcess com
  o PspAllocateThread e o PspInsertProcess/PspInsertThread). Todo processo
  de usuário nasce ali: o `run_windows_process` e o `run_service`
  (`ps/user/process.rs`, que só monta o pedido e executa o processo
  criado, `run_created` = `start_created` + `wait_started`) e os
  autotestes. O pedido traz a imagem (caminho
  NT de um arquivo do volume, arquivo do volume ou bytes), o nome curto e
  os parâmetros, opcionalmente o pai de quem herdar os handles, e o
  `ImageRequest` (o InitState do PS_CREATE_INFO). A ordem:
  abrir a imagem (um arquivo do volume é aberto como o IoCreateFileEx do
  NtCreateUserProcess: SYNCHRONIZE | FILE_EXECUTE mais o
  AdditionalFileAccess, FILE_SHARE_READ | FILE_SHARE_DELETE, conferido
  contra as aberturas existentes e, recusado, de novo sem o acesso
  adicional) e ler o layout, recusando as características que o pedido
  proíbe (uma falha não cria
  nada: `CreateFailure::FileOpen`/`ExeFormat`); `create_process` (EPROCESS,
  PID, raiz própria, `ProcessState`, seção de imagem); a herança de handles
  do pai, se pedida; anexado ao processo
  novo, as cópias de sistema, o executável, a pilha
  (`ps/user/memory::create_user_stack`, o RtlCreateUserStack do
  PspSetupUserStack, com o MaximumStackSize e o CommittedStackSize da
  imagem; o NtCreateThreadEx usa o mesmo, com os tamanhos pedidos ou os da
  imagem no lugar dos zeros: a reserva inteira, só o commit comitado no
  topo, StackLimit na base dele, 3 páginas PAGE_GUARD logo abaixo para a
  pilha crescer pela falta, DeallocationStack na base da reserva), a PEB
  (`mm/peb_teb.rs`, o MmCreatePeb: imagem, ApiSetMap +0x68, NLS, heap,
  versão, subsistema da imagem; PEB.Ldr NULL para a ntdll;
  CriticalSectionTimeout com o MmCriticalSectionTimeout, os segundos do
  `CriticalSectionTimeout` do Session Manager vezes -10.000.000, 30 dias
  por padrão; com mais de uma hora a ntdll espera sem prazo numa seção
  crítica), a PEB_LDR_DATA
  do loader do kernel (`loader::create_kernel_ldr`), o manifesto embutido
  com DetectManifest (o PspLocateInPEManifest: o RT_MANIFEST 1, primeiro
  idioma, pela pesquisa de recursos da Rtl em SectionBaseAddress; achado,
  a VA no processo novo e o tamanho voltam no `CreatedProcess` e o bloco de
  parâmetros leva RTL_USER_PROC_APP_MANIFEST_PRESENT), os parâmetros
  (`ps/process_parameters.rs`, o RtlCreateProcessParametersEx: bloco
  com ImagePathName, CommandLine, diretório corrente, DLLs, título,
  desktop, shell, runtime, ambiente com EnvironmentSize, console e handles
  padrão, entregue NORMALIZED com os Buffers absolutos, como o
  PspCopyAndFixupParameters deixa; o PS_CREATE_INFO leva o Flags com o
  NORMALIZED no CurrentParameterFlags), a TEB (`peb_teb::create_teb`, o MmCreateTeb, também
  usado pelo NtCreateThreadEx) e o CONTEXT inicial do LdrInitializeThunk; a
  KTHREAD com pilha de kernel própria; as notificações de thread no
  contexto de quem cria e as de carga de imagem anexadas ao processo novo.
  O processo sai parado (`CreatedProcess`); descartado sem rodar, termina
  com STATUS_CANCELLED, e toda falha depois do `create_process` passa pelo
  fim do processo (`create::exit_process`). O pedido também pode declarar
  outro pai (`process::set_parent`: o PID dele nas notificações e em
  InheritedFromUniqueProcessId) e criar a thread principal suspensa
  (THREAD_CREATE_FLAGS_CREATE_SUSPENDED; o registro no despacho respeita a
  contagem). Teste: `ntos/test/multiprocess/create_path.rs`.
- **NtCreateUserProcess**: o handler é o adaptador fino
  `ps/user/process.rs::nt_create_user_process` (os onze argumentos), e o
  corpo fica em `ps/create_context.rs` (o papel do
  PspBuildCreateProcessContext). Tudo é sondado e capturado da memória do
  chamador antes de agir: o PS_CREATE_INFO (`inc/types/wdk.rs::PsCreateInfo`,
  0x58 bytes do 19041, com as vistas por estado; o PspCaptureCreateInfo
  exige PsCreateInitialState e decodifica o InitState: WriteOutputOnExit,
  DetectManifest, ProhibitedImageCharacteristics, AdditionalFileAccess), a PS_ATTRIBUTE_LIST copiada
  uma vez (honra ImageName, ParentProcess com PROCESS_CREATE_PROCESS,
  PriorityClass (um UCHAR lido pelo ponteiro do Value, com Size 1, como o
  CreateProcessInternalW o passa), ProtectionLevel (o processo novo recebe o PS_PROTECTION
  pedido se quem cria for protegido e o dominar) e as saídas ClientId,
  TebAddress e ImageInfo, e JobList (os handles de job referenciados com
  JOB_OBJECT_ASSIGN_PROCESS); recusa com STATUS_NOT_SUPPORTED DebugObject,
  Token, SecureProcess e UmsThread; aceita sem efeito, no log, os demais que o kernel32
  passa; número desconhecido, repetido ou tamanho errado dão
  STATUS_INVALID_PARAMETER), o RTL_USER_PROCESS_PARAMETERS normalizado ou não
  (`process_parameters::capture`: a estrutura copiada até o Length, cada
  texto sondado com a capacidade pedida, RuntimeData como bytes, ambiente
  por EnvironmentSize ou até o NUL duplo, os escalares do STARTUPINFO), os
  OBJECT_ATTRIBUTES (sem nome; OBJ_INHERIT vai para o handle) e as flags
  (as PROCESS_CREATE_FLAGS_* que pedem outro tipo de processo dão
  STATUS_NOT_SUPPORTED; INHERIT_HANDLES vira o `inherit_handles_from` do
  pedido: o pai declarado no ParentProcess ou, sem ele, quem chama; a
  herança copia as linhas OBJ_INHERIT das duas tabelas do pai, a de usuário
  e a do Object Manager, com os mesmos valores; CREATE_SESSION abre uma
  sessão nova, `mm/session.rs`, e sem ela o processo entra na sessão do
  pai). Depois o
  caminho único cria o processo, `start_created` o põe no despachante, os
  handles do processo e da thread entram na tabela de quem chamou com o
  acesso pedido (genéricos mapeados, MAXIMUM_ALLOWED como o total do tipo) e
  as saídas vão para as VAs sondadas, como o PspUpdateCreateInfo: o estado
  sempre (PsCreateSuccess, PsCreateFailOnFileOpen, PsCreateFailExeFormat) e
  os campos dele só com WriteOutputOnExit (o kernel32 o liga; o
  RtlCreateUserProcess da ntdll não). No PsCreateSuccess: OutputFlags
  (ProtectedProcess e ProtectedProcessLight do EPROCESS.Protection,
  AddressSpaceOverride do EPROCESS.Flags, ManifestDetected),
  ManifestAddress/ManifestSize, FileHandle (o exe, aberto na tabela de quem
  chamou com o acesso da abertura da criação, `file_io::open_resolved`) e
  SectionHandle (a seção de imagem do processo, SECTION_ALL_ACCESS, um
  `InheritedObject`), o bloco de parâmetros, o Flags dele
  (CurrentParameterFlags) e a PEB; no PsCreateFailExeFormat, o
  DllCharacteristics. Com o FileHandle válido o kernel32 toma o caminho de
  disco fixo da mensagem de SxS ao csrss, e com
  RTL_USER_PROC_APP_MANIFEST_PRESENT o sxssrv gera o contexto de ativação
  do processo a partir do manifesto embutido. O KPROCESS é sinalizado no
  término (`terminate_process`), então a espera no handle do processo
  acorda. Teste: `ntos/test/multiprocess/create_user_process.rs`, um pai
  real no anel 3 que chama o handler com tudo na memória dele, imprime
  `MULTIPROCESS_OK`.
- **Memória de usuário de outro processo**: o kernel só toca a memória de
  usuário do processo corrente; para a de outro, anexa ao dono antes, como
  o KeStackAttachProcess do NT. O escopo é `ps/process_context.rs::
  with_process`, que troca o KAPC_STATE e carrega a raiz do alvo como o
  attach (`ke/context_switch.rs`), voltando à do processo restaurado. Rodam
  anexados: a cópia de conclusão de `device_io` (SystemBuffer e IOSB, que o
  pump do despachante conclui no contexto de quem o chamou), a cópia final do
  IofCompleteRequest de um IRP de modo usuário (IOSB e buffer vão para o
  processo de Irp->Tail.Overlay.Thread, como a APC de conclusão do NT; um
  processo que já saiu não recebe a cópia), o post-mortem no fim do
  processo (`create::finish_exit`, de qualquer contexto), a criação
  do processo (`ps/create.rs`: imagem, PEB, parâmetros, TEB e o CONTEXT
  inicial, e as notificações de carga de imagem do executável e da ntdll,
  com o PID dele), a criação de workers de fábrica (já era) e cada lado da
  cópia do MmCopyVirtualMemory (a leitura anexada à origem, a gravação ao
  destino). A
  notificação de carga de imagem do loader do kernel vem depois de a imagem
  entrar no VAD do processo, onde os callbacks a leem.
  As entregas que a thread recebe numa espera sondada (pacotes de conclusão,
  mensagens ALPC, workers de fábrica) rodam como a própria thread
  (`refresh_ready_user_threads` a torna a corrente), e as APCs de kernel e
  as conclusões de E/S adiadas drenadas também (`drain_kernel_apcs`); os pumps de ALPC, de pacotes de
  espera e de timers só mexem em memória do kernel. O modo estrito de posse
  (seção 3.3) confere tudo isso. Teste: `ntos/test/multiprocess/ownership.rs`.
- **Arquivos de paginação e working set** (`mm/paging_file/`,
  `mm/working_set.rs`, `mm/modified_writer.rs`, `mm/commit.rs`,
  `mm/memory_information.rs`). Estruturas e formatos do ntoskrnl 19041.
  - `paging_file/create.rs`: NtCreatePagingFile (MiCreatePagingFile).
    Confere Priority, SeCreatePagefilePrivilege, tamanhos e nome. Cria o
    arquivo com IO_OPEN_PAGING_FILE e a DACL de Administradores e
    LocalSystem, põe o fim do arquivo no tamanho mínimo e zera a primeira
    página por E/S de paginação. O adaptador de usuário está em
    `ps/user/memory.rs`.
  - O smss.exe real chama o NtCreatePagingFile com o valor `PagingFiles` do
    Session Manager (`cm/session_manager.rs`: `D:\pagefile.sys 192 256`).
    Antes ele abre `Control\CrashControl` e lista os volumes com o
    ProcessDeviceMap (`ob/device_map.rs`, montado a partir dos links `X:`
    do `\??` do processo, o `\GLOBAL??` para o SYSTEM).
  - Até 16 arquivos, cada um com um `_MMPAGING_FILE` do PDB no pool. O
    espaço livre é um bitmap do tamanho máximo; as páginas 0 e 1 ficam
    reservadas.
  - `commit.rs`: commit do sistema. O limite começa nas páginas físicas e
    sobe com o tamanho de cada arquivo. A página privada comitada cobra do
    sistema antes do processo. Acima do limite, com o limite abaixo do
    limite máximo, a cobrança espera um pedido de extensão dos arquivos e
    recomeça se algum cresceu; senão a alocação falha com
    STATUS_COMMITMENT_LIMIT. Uma cobrança que passa de 90% do limite pede a
    extensão sem esperar.
  - `paging_file/extend.rs`: extensão até o MaximumSize, como no 19041. O
    pedido é um `_MMPAGE_FILE_EXPANSION` do PDB, numa fila atendida por uma
    thread de prioridade 19 (o papel da MiDereferenceSegmentThread):
    MiIssuePageExtendRequest, MiExtendPagingFiles,
    MiAttemptPageFileExtension (o novo fim vai ao file system pelo
    IoSetInformation com FILE_END_OF_FILE_INFORMATION_EX; a extensão é de
    pelo menos 64 MB, ou 16 MB na segunda tentativa, e deixa 256 MB livres
    no volume) e MiFinishPageFileExtension. O limite de commit sobe com o
    que cresceu. O modified page writer sem espaço chama o
    MiPageFileNoFreeSpace, que faz o pedido estático (commit acima de 80%
    do limite, ou 4096 páginas ou mais esperando o arquivo); quem grava
    páginas para conseguir memória espera esse pedido terminar e continua
    gravando no espaço novo. No D: (file system embutido), o
    IoSetInformation de FileEndOfFileInformation num FILE_OBJECT muda o
    tamanho do arquivo no volume (`io/file/zw.rs`). O volume do boot do
    smss tem 800 MB livres: o máximo do arquivo, os 256 MB do
    `C:\swapfile.sys` (o arquivo de troca de working sets que o smss cria
    no volume do sistema, fora do commit), os 256 MB que a extensão deixa e
    folga.
  - E/S: IoPageRead e IoSynchronousPageWrite (IRP_PAGING_IO,
    `io/paging_io.rs`), enviados ao dispositivo do IoGetRelatedDeviceObject.
    No D: (file system embutido) o volume atende esses IRPs direto nas runs
    do arquivo (`drivers/fs/volume_device.rs`, `Ntfs::paging_write`).
  - Página fora do working set: entrada no `paging` da região
    (`ps/user/memory.rs`) e PTE de transição ou de arquivo de paginação
    (PageFileLow = arquivo, PageFileHigh = página).
  - Corte do working set: roda quando falta memória (recuperador do PFN).
    Usa segunda chance pelo bit Accessed. Página suja vai para a lista de
    modificadas; página limpa com cópia no arquivo vai para a de reserva.
  - MiModifiedPageWriter: thread de prioridade 18 que grava as modificadas
    em clusters de até 16 páginas. Quem espera memória também grava, no
    próprio contexto.
  - Faltas: a de transição volta a mapear o frame sem E/S; a de arquivo de
    paginação lê a página num frame novo. Falta de usuário, falta de kernel
    em VA de usuário e sondas de `guest_memory` passam por
    `working_set::page_in`. MmProbeAndLockPages trava os frames até o
    MmUnlockPages; num endereço de sistema, traz cada página pela falta do
    provedor dono (vistas de sistema, imagens, pool paginável) e a retém
    contra a expulsão (`mm/io_pins.rs`) até o MmUnlockPages.
  - NtLockVirtualMemory e NtUnlockVirtualMemory (`mm/virtual_lock.rs`, com
    o ZwUnlockVirtualMemory): as validações do MiLockUnlockCommon (MapType
    MAP_PROCESS/MAP_SYSTEM, faixa de usuário, PROCESS_VM_OPERATION e o
    SeLockMemoryPrivilege do MAP_SYSTEM em UserMode) e a faixa em páginas
    inteiras. A trava pede páginas comitadas de uma alocação privada
    (STATUS_ACCESS_VIOLATION senão), traz de volta as que estão fora do
    working set e marca cada página com o tipo; o corte não leva as
    travadas. Tudo já travado dá STATUS_WAS_LOCKED; a destrava de uma página
    não travada no tipo dá STATUS_NOT_LOCKED. O decommit leva a trava. O
    VirtualLock do LsaInitializeProtectedMemory do lsasrv passa por aqui.
    A trava de uma vista de seção fica recusada (STATUS_NOT_SUPPORTED), já
    que o corte do OpenNT só toca alocações privadas.
  - NtQuerySystemInformation: SystemPerformanceInformation e
    SystemPageFileInformation(Ex).
  - Diferenças: sem working set por processo; pilha inicial, PEB, TEB e
    parâmetros do processo ficam residentes; o writer é síncrono; o arquivo
    cresce mas não encolhe (sem MiAttemptPageFileReduction).
  - Testes: `ntos/test/paging_file.rs` (fase 7) e o [[teste]] `pagefile`
    (`PAGEFILE_OK` e o `MEMORY_PRESSURE_OK` de
    `ntos/test/memory_pressure.rs`).
- **Montagem de volumes por um file system real** (`io/file_system.rs`,
  `io/parse.rs`, `drivers/storage/ata_volume.rs`), como no NT:
  - IoCreateDevice dá a todo dispositivo montável (disco, CD-ROM, fita,
    disco virtual) um VPB (IopCreateVpb) e o DeviceLock sinalizado, e o
    SectorSize inicial do tipo.
  - A abertura de `\Device\<volume>\<resto>` (ZwCreateFile, `io/parse.rs`, o
    ramo de arquivo do IopParseDevice) acha o DEVICE_OBJECT com VPB no
    prefixo e chama `check_vpb_mounted` (IopCheckVpbMounted): sem volume
    montado, `mount_volume` (IopMountVolume) percorre a fila de file systems
    do tipo do dispositivo e manda IRP_MJ_FILE_SYSTEM_CONTROL/
    IRP_MN_MOUNT_VOLUME (IRP_MOUNT_COMPLETION | IRP_SYNCHRONOUS_PAGING_IO,
    com o VPB e o topo da pilha do dispositivo real) ao topo da pilha de cada
    CDO, soltando o banco durante a chamada; o primeiro que aceita fica com
    o volume e `mount_initialize_vpb` marca o VPB, acerta o StackSize do
    dispositivo de volume e liga a DEVOBJ_EXTENSION. O FILE_OBJECT nasce com
    DeviceObject = dispositivo real, Vpb e o nome restante, e o
    IRP_MJ_CREATE vai ao dispositivo de volume com o IO_SECURITY_CONTEXT (o
    ACCESS_STATE do SeCreateAccessState) e as opções do NT. A abertura retém
    o VPB e o dispositivo até o IRP_MJ_CLOSE; leituras e escritas seguem o
    caminho comum (IoGetRelatedDeviceObject pelo VPB). O IoVerifyVolume
    remonta pelo mesmo caminho. Sem RAW nem reconhecedores; a abertura
    direta de um dispositivo (sem nome restante) não monta. Nela o
    FILE_OBJECT também guarda (e referencia) o dispositivo do nome, o
    parseDeviceObject, e não o topo da pilha: quem abre um link de interface
    (o IoGetDeviceObjectPointer do partmgr.sys no do volmgr.sys) acha no
    FileObject->DeviceObject o PDO que a registrou, e o IRP vai ao topo.
  - O volume que os file systems reais montam é o segundo disco IDE,
    exposto pelo driver ATA do kernel como `\Device\AtaVolume1` (DEVICE_OBJECT
    nativo respondido pelo próprio kernel, com VPB, DO_DIRECT_IO, geometria
    do IDENTIFY DEVICE e os IOCTLs de disco, armazenamento e mount manager
    da montagem; o DRIVER_OBJECT `\Driver\AtaVolume` tem a mesma rotina em
    cada IRP_MJ_*, porque um file system pode chamar o MajorFunction do
    dispositivo alvo sem o IofCallDriver). O leitor NTFS do kernel continua dono do disco como D:,
    então as escritas do file system ficam numa sobreposição em memória por
    página de 4 KB, que as leituras do volume aplicam; o disco não muda
    durante o boot. A sobreposição é o cache de escrita do dispositivo: na
    fila de última chance do desligamento (depois do IRP_MJ_SHUTDOWN dos
    file systems) o volume grava no disco só os setores que o file system
    gravou e manda o FLUSH CACHE; dali em diante as escritas vão direto.
  - O driver ATA interno (`drivers/storage/ata_pio.rs`) trata falhas como a
    pilha de disco do 19041 num disco IDE (disk.sys e classpnp.sys sobre
    atapi.sys e ataport.sys). O prazo de cada comando é o TimeOutValue do
    disco (10 s, ou o valor de `Services\disk\TimeOutValue`, lido quando a
    hive SYSTEM existe), e o do FLUSH CACHE é quatro vezes ele. Um comando
    vencido leva o canal ao reset (o SRST do atapi.sys, com até 60 s para o
    BSY cair); um comando que o dispositivo termina com erro volta sem
    reset. Nos dois casos o pedido é mandado de novo até 4 vezes (o
    MaxNumberOfIoRetries do classpnp, ou o valor de `Control\Classpnp`)
    antes de falhar. Cada tentativa que falha sai numa linha `[ata]` da
    serial (comando, drive, LBA, setores, status, erro, status do bus
    master e tempo), e o primeiro pedido que só conclui numa nova tentativa
    imprime `ATA_RETRY_OK`. O autoteste da fase 4 confere o reset do canal e
    os prazos lidos do Registro; o teste `ata-falha` (`--ata-fault=read`)
    põe o volume de dados atrás do filtro blkdebug do QEMU, que devolve um
    erro de E/S a uma leitura do kernel. Só o driver interno programa o
    canal, sob o lock dele: um comando de DMA não reescreve o que o
    anterior, terminado bem, deixou nos registradores (o drive selecionado
    sem BSY, o endereço da tabela PRD, a direção do bus master, o status do
    bus master limpo); a espera lê o status do bus master e só no bit de
    interrupção lê o do dispositivo. Uma falha, um reset, um comando de PIO
    ou o atapi.sys assumindo a controladora esquecem esse estado.
  - O NTFS interno lê os registros do MFT e os blocos INDX dos diretórios
    pelo cache de setores (`drivers/storage/sector_cache.rs`), como o NTFS
    do Windows os lê pelo Cache Manager: unidades alinhadas de 4 KB em
    frames do PFN (até 1/64 da RAM e 16 MB, com despejo da menos usada). O
    cache é o primeiro provedor de residência: na pressão do PFN ele
    devolve frames antes de qualquer página ir para o arquivo de paginação.
    Toda escrita do OpenNT no disco passa pelo `ata_pio::write_sectors` (ou
    a versão PIO), que tira do cache as unidades cobertas antes e depois do
    comando; uma leitura que cruzou uma escrita não entra no cache, e as
    escritas pendentes de uma transação continuam sobrepostas pelo volume.
    Com `--storage=real` o cache se esvazia e deixa de guardar antes de o
    atapi.sys assumir a controladora. Antes, cada `stat`,
    passo de caminho e enumeração de diretório lia o disco de novo: no boot
    até a barra de tarefas, um terço do tempo da CPU ia para o DMA dessas
    leituras. Acima dele, os diretórios lidos e os layouts do `Ntfs` e o
    stat, os bytes e os blocos de leitura de cada arquivo do volume
    (`volume_files`) caem por registro do MFT: o commit de uma transação
    marca com a geração nova do drive só os registros que ela regravou, e
    cada cache guarda os registros de que depende (os diretórios do caminho
    e o arquivo).
  - O `--start-driver` de um driver de file system (Type 2) cria o volume e
    abre e lê um arquivo conhecido pelos exports
    (`ntos/test/file_system_mount.rs`); a fase 6 cobre o caminho com dois
    file systems sintéticos. Com `--trace-driver-api`, as APIs chamadas na
    montagem também vão para a serial.
  - O volume é um NTFS 3.1 completo (`xtask/src/ntfs_image.rs`): registros
    de arquivo de 4 KB, os arquivos de metadados 0..11 com o número de
    sequência do NTFS ($MFT com o $BITMAP não residente, que a montagem
    pré-carrega, $MFTMirr, $LogFile de 2 MB com as páginas em
    0xFF — um log novo, que o LFS inicializa —, $Volume 3.1, $AttrDef com a
    tabela do ntfs.sys, $Bitmap, $Boot, $BadClus com o $Bad esparso,
    $Secure com o descritor comum e os dos nós no $SDS (cada entrada
    alinhada a 16 bytes num bloco de 256 KB, com a cópia no bloco seguinte;
    a que não cabe vai para o próximo bloco primário) e os índices
    $SDH/$SII, residentes ou em B-tree com blocos INDX, $UpCase pelo
    RtlUpcaseUnicodeChar, $Extend; 12..15 reservados), $Quota, $ObjId e
    $Reparse depois dos registros de usuário (o NTFS só aceita uma entrada de
    índice que aponte um registro abaixo de 16 na raiz), os índices $I30 nomeados e em B-tree quando não cabem no
    registro, e a cópia do setor de boot no último setor, fora do volume.
    Nas runlists, a contagem de clusters também leva o byte de sinal livre,
    porque o ntfs.sys a lê com sinal: o $Bad do volume de 41796 clusters do
    `nvme.img` (0xA344) vai em três bytes (44 A3 00); em dois seria um run
    de -23740 clusters e o NtfsCheckFileRecord recusaria o $BadClus
    (STATUS_FILE_CORRUPT_ERROR na montagem).
    Os nós do volume (`ntfs_image::Node`) dão a um caminho atributos e
    descritor de segurança próprios (um SecurityId por descritor
    distinto, a partir de 0x101) e põem no volume diretórios vazios; o
    $STANDARD_INFORMATION e o $FILE_NAME guardam os atributos sem o de
    diretório, que o NTFS marca no registro (e no
    DUP_FILE_NAME_INDEX_PRESENT). Os arquivos do Windows levam o
    descritor que têm nesta máquina, sem SID de conta
    (`xtask/src/host_security.rs`): a raiz leva o de
    `C:\Windows\System32` (ela responde também por `C:\` e `C:\Windows`),
    uma pasta casa com a pasta daqui pelos nomes, e um arquivo gerado (as
    hives, o PE do kernel, o HELLO.TXT) ou uma pasta sem par herda do pai
    com a herança do NTFS, com o dono Administradores e o grupo SYSTEM de
    um criador SYSTEM. No boot do smss o volume leva também as pastas
    vazias de uma instalação nova que a cadeia usa (ProgramData, o Temp, os
    perfis de serviço, o perfil do SYSTEM, LogFiles e Logs). O kernel ainda
    não lê esses descritores.
    O leitor do kernel lê o mesmo volume; a listagem dele esconde os
    registros abaixo de 16, como a enumeração do NTFS, e o stat soma o
    FILE_ATTRIBUTE_DIRECTORY aos atributos de um diretório.
  - O ntfs.sys importa o clfs.sys (pelo ext-ms-win-fs-clfs) e o clipsp.sys
    (pelo ext-ms-win-ntos-clipsp, que importa o fltmgr.sys): o carregador os
    resolve como dependências, do volume e validados pelo Code Integrity
    com os catálogos achados pelo hash da imagem no CatRoot. O clfs.sys e o
    fltmgr.sys sobem pelo DriverEntry (drivers de boot no Windows) e o
    clipsp.sys pelo DllInitialize. O volume ATA responde o
    IOCTL_MOUNTDEV_QUERY_STABLE_GUID, que o FsRtlVolumeDeviceToCorrelationId
    pede na montagem.
  - O CDO do ntfs.sys é \Ntfs, na raiz do namespace (o volume do kernel
    fica no seu dispositivo, sem nome na raiz). O DriverEntry registra o
    file system e o FltMgr se anexa ao CDO pela notificação de registro; o
    IoGetDeviceObjectPointer que ele faz de \Device\NamedPipe leva o
    IO_SECURITY_CONTEXT no IRP_MJ_CREATE (todo IRP_MJ_CREATE do I/O Manager
    leva), e o ObQueryNameString acha objetos nomeados fora de \Device.
    O mount pelo FltMgr chega ao NtfsFsdFileSystemControl, que posta a
    montagem à FSP (ExQueueWorkItem) e devolve STATUS_PENDING; o FltMgr
    espera, e o item roda no pump dessa espera. O NtfsMountVolume vai até o
    fim: os streams internos sem PinAccess que ele solta ficam para o lazy
    writer (o IRP_MJ_CLOSE vem depois, como no Windows) e o file system
    anuncia a montagem (FsRtlNotifyVolumeEventEx); os itens de pós-montagem
    (EFS, $Extend\$Deleted) rodam depois de o IopMountVolume soltar o
    DeviceLock. O teste abre e lê HELLO.TXT pelo Cache Manager e cria,
    grava, fecha, reabre e lê de volta um arquivo novo pelo ntfs.sys; o
    lazy writer grava depois as páginas sujas pela sobreposição do volume.
  - O ntfs.sys exige o espaço de nomes certo no $FILE_NAME: um nome só
    Win32 (1) precisa do par curto do DOS (2), e o NtfsUpdateFileNameInParent
    dá STATUS_FILE_CORRUPT_ERROR sem ele. O xtask (e o gravador NTFS do
    kernel) grava os nomes 8.3 maiúsculos como Win32+DOS (3), como o NTFS,
    e os demais no espaço POSIX (0).
- **Minifiltros reais sobre o Filter Manager** (`cm/service/file_system_filters.rs`,
  `mm/prefetcher_file_info.rs`, `ntos/test/minifilters.rs`):
  - As chaves do FltMgr e dos minifiltros são as da instalação (Type 2,
    Group, DependOnService, SupportedFeatures e a subchave `Instances` com
    a DefaultInstance e a Altitude/Flags de cada instância), com Start 3
    como os outros drivers inbox. O DependOnService faz o gerenciador de
    serviços subir o FltMgr pela chave dele antes do primeiro minifiltro;
    um ntfs.sys iniciado depois acha o `\Driver\FltMgr` já carregado pelo
    import do clipsp.sys. O FltRegisterFilter de cada minifiltro lê as
    `Instances` pelo caminho do serviço que o DriverEntry recebe.
  - O DriverEntry do FileInfo abre `Session Manager\Memory Management\PrefetchParameters`
    (a semente leva o EnablePrefetcher = 3 da instalação) e se liga ao
    prefetcher pelo PfFileInfoNotify: números de sequência dos streams
    (Type 7) e o registro da sua interface (Type 0xA, que entrega ao
    RegisterGlobalBlockNotify do FileInfo a rotina de conflito do
    prefetcher, uma rotina por ponteiro de `hal/amd64/routine_stubs.rs`).
    As notificações de E/S e de nomes só alimentariam traços de cenário e o
    log do Superfetch, que o OpenNT não tem.
  - O FileInfo e o Wof se anexam sozinhos a todo volume NTFS (no
    FltStartFiltering aos já montados, na montagem aos novos). O storqosflt,
    o bindflt e o wcifs só aceitam a anexação manual no InstanceSetup (a
    que os serviços de QoS de armazenamento e de contêiner pedem pelo
    FilterAttach); o teste anexa o storqosflt e o bindflt por
    FltAttachVolume com a instância padrão da chave. O wcifs carrega e se
    registra, mas o InstanceSetup dele pede o nome GUID do volume
    (FltGetVolumeGuidName, IOCTL_MOUNTMGR_QUERY_POINTS ao mount manager), e
    o volume ATA ainda não se anuncia ao mount manager
    (MOUNTDEV_MOUNTED_DEVICE_GUID): STATUS_INVALID_PARAMETER.
  - O que as cargas e as anexações pediram do kernel: os caminhos lentos
    de push lock (ExfAcquirePushLockExclusive/Shared, ExfReleasePushLock),
    PsSetCurrentThreadPrefetching, IoGetSiloParameters, _i64tow_s, o
    RtlDecompressBuffer/Ex e o RtlDecompressFragment (o Wof), o
    ZwQuerySystemInformation(SystemBasicInformation) de modo kernel (o
    FileInfo mede a memória física por ela), o
    WmiQueryTraceInformation(FltIoNotifyRoutinesClass), que dá ao FltMgr o
    endereço da tabela de rotinas de notificação de E/S dos minifiltros (NULL
    sem sessão de rastreamento; o FltMgr a lê em cada callback), e a
    largura certa dos argumentos do RtlInitializeSid (UCHAR) e do
    RtlSubAuthoritySid (ULONG). A extensão do FILE_OBJECT
    (IopAllocateFileObjectExtension) é uma só, do I/O Manager, também
    para os contextos por FILE_OBJECT do FsRtl que o FltMgr usa, e é
    liberada com o FILE_OBJECT.
    O volume ATA responde o IOCTL_DISK_GET_CLUSTER_INFO como o partmgr.sys
    responde por um disco fora de cluster (o storqosflt pergunta se o volume
    é um CSV oculto), e o volume do xtask marca o $Secure e os índices do
    $Extend com DUP_VIEW_INDEX_PRESENT, sem o qual o ntfs.sys recusa abrir
    `$Extend\$Reparse:$R:$INDEX_ALLOCATION` (o Wof enumera os pontos de
    reparse na anexação).
  - O FltCreateFileEx de um minifiltro chega ao IoCreateFileEx com o
    IO_DRIVER_CREATE_CONTEXT (`io/parse.rs`): a lista de ECPs vai no
    Irp->UserBuffer do IRP_MJ_CREATE, onde o FltMgr acha a sua (que diz
    abaixo de qual instância a abertura começa), e a dica de dispositivo,
    conferida na pilha do volume, recebe o IRP e fica no FILE_OBJECT para o
    IoGetRelatedDeviceObject. A abertura sem nome de um volume montado com
    acesso além do de uma abertura direta (FILE_READ_ATTRIBUTES, READ_CONTROL,
    WRITE_DAC, WRITE_OWNER, SYNCHRONIZE, ACCESS_SYSTEM_SECURITY) vai ao file
    system como a abertura do volume, como no IopParseDevice: é a do Wof e a
    do wcifs, que consultam o volume (FileFsSizeInformation) na anexação.
    Sem o RAW, um volume ainda não montado continua aberto direto no
    dispositivo.
  - O teste `minifilters` pergunta ao FltMgr, pelos exports dele, os
    filtros, os volumes e as instâncias (InstanceFullInformation), confere
    filtro/instância/altitude no volume NTFS, abre e lê HELLO.TXT abaixo da
    instância de um filtro (FltCreateFileEx, FltReadFile, FltClose) e repete
    as operações de arquivo do teste do ntfs.sys com a pilha de filtros
    sobre o volume, cujo topo é o dispositivo do FltMgr.
- **Worker threads do sistema** (`io/work_items.rs`): como no NT, o
  ExQueueWorkItem/IoQueueWorkItem põe o item na fila e as worker threads
  (o ExpWorkerThread) o executam em PASSIVE_LEVEL, cada item na pilha de uma
  delas, no processo System. O ExpWorkerInitialization da fase 1
  (`initialize_workers`, logo depois dos exports, como o ExInitSystem antes
  do IoInitSystem) cria as quatro workers iniciais; antes disso a fila só
  guarda os itens, que rodam quando elas nascem. A worker sem item espera o
  evento de sincronização da fila, que o item novo sinaliza. Cada item roda
  na prioridade do seu tipo de fila (o ExpTypeToPriority do ntoskrnl 19041 e
  a tabela ExpBuiltinPriorities: Critical 13, Delayed 12, HyperCritical 15,
  Normal 8, Background 7, RealTime 18, SuperCritical 14, e QueueType - 32 de
  32 em diante). Uma worker que espera dentro de um item não roda outro.
  Como o gerenciador das filas do NT (ExpWorkQueueManagerThread), quando
  nenhuma worker está livre e o item pronto mais antigo espera há 1 s, o
  pool ganha uma worker, no máximo uma por segundo e até 64 (`balance`, que
  os pumps do despachante chamam: o `pump_kernel`, os pumps do
  KeDelayExecutionThread e o laço ocioso). Nenhum item roda no contexto de
  boot nem na pilha de quem espera: o acpi.sys que repassa o START da ponte
  PCI-ISA ao pci.sys numa worker e espera o work item do pci.sys, o
  FsRtlWaitForSmssEvent sem smss e o WorkerThread do mountmgr.sys à espera
  do `\Device\VolumesSafeForWriteAccess` só prendem a própria worker.
  `run_queue` não executa nada: espera que os itens já enfileirados
  terminem ou que as workers deles parem numa espera (KTHREAD.State
  Waiting), saindo das prontas numa thread e girando o despachante no
  contexto de boot. Testes: `work_items_on_worker_threads` na fase 6 (os
  itens em workers do System, o item parado que só prende a sua worker, a
  prioridade por tipo de fila) e `stalled_worker`
  (`test/platform_support.rs`: o item que uma worker espera roda noutra; com
  todas as workers presas, o item novo roda numa worker que o gerenciador só
  cria depois do intervalo).
- **Volumes seguros para escrita** (`fsrtl/volume_support.rs`): como o
  FsRtlInitSystem do 19041 (FsRtlInitializeSmssEvent, rva 0xa6bb14), a
  fase 1, antes dos drivers, cria o evento de notificação permanente
  `\Device\VolumesSafeForWriteAccess`, não sinalizado, e enfileira na
  DelayedWorkQueue o FsRtlWaitForSmssEvent, que o espera sem prazo, liga o
  FsRtlpVolumeStartupApplicationsComplete (que o
  FsRtlAreVolumeStartupApplicationsComplete devolve) e solta a referência.
  Quem sinaliza é o smss.exe: o SmpInit abre o evento (NtOpenEvent,
  EVENT_ALL_ACCESS) e o SmpLoadDataFromRegistry o sinaliza logo depois dos
  comandos BootExecute; no boot do smss real (teste smss-csrss) o
  FsRtlWaitForSmssEvent termina antes de o smss criar o smss da sessão, e a
  serial leva `[fsrtl] \Device\VolumesSafeForWriteAccess sinalizado`. O
  WorkerThread do mountmgr.sys espera o mesmo
  evento antes de gravar nos volumes. Sem smss ninguém o sinaliza e as duas
  workers ficam paradas, como no NT. Teste: `fsrtl_smss_event` (fase 6: o
  evento, a abertura pelo nome com ZwOpenEvent, a worker parada nele e o
  FALSE do FsRtlAreVolumeStartupApplicationsComplete).
- **Lazy writer do Cache Manager** (`cc/lazy_writer.rs`): o
  CcScheduleLazyWriteScan arma o ScanTimer (CcFirstDelay, 3 s; FastScan
  acorda já), a DPC dele acorda a thread do lazy writer — uma thread de
  sistema do Cc, na própria pilha, criada na primeira CcInitializeCacheMap,
  cujas esperas (nos recursos do file system, nas escritas) bloqueiam de
  verdade. A passada
  (CcLazyWriteScan) faz o CcWriteBehind de cada mapa sujo ou à espera de
  remoção: AcquireForLazyWrite(Wait=TRUE), escrita das páginas sujas,
  ReleaseFromLazyWrite e, sem FILE_OBJECTs nem páginas sujas, a remoção do
  SHARED_CACHE_MAP, que solta a referência do stream file — de onde vem o
  IRP_MJ_CLOSE do file system. O último CcUninitializeCacheMap segue o
  NT: mapa sem PinAccess e sem evento, com escrita em curso ou sujo fica
  para o lazy writer (FALSE); os demais saem na hora (TRUE). Um mapa que
  ganha páginas sujas agenda a passada, que se reagenda por CcIdleDelay
  (1 s) enquanto houver trabalho; o CcWaitForCurrentLazyWriterActivity
  pede uma passada rápida e espera o fim dela. Testes: os de Cc da fase 6
  (`cc_cache_map_exports`, `cc_copy_exports`, `cc_pin_exports`,
  `cc_flush_exports`, `cc_mdl_exports`).
- **Pipes nomeados e mailslots pelos npfs.sys e msfs.sys reais**
  (`cm/service/inbox_drivers.rs`, `io/file/pipe_mailslot.rs`,
  `io/file/irp_service.rs`, a abertura de `ps/user/files.rs`):
  - As chaves Npfs e Msfs são as da instalação (Type 2, Start 1, Group
    "File system", sem ImagePath; o Npfs com a subchave Aliases) e os dois
    binários estão no volume em todo boot, então o laço dos drivers de
    sistema (Start <= 1) os carrega no boot comum e no do smss. O DriverEntry
    deles cria `\Device\NamedPipe` e `\Device\Mailslot` (nenhum dos dois se
    registra como file system montável). Os dispositivos DOS `\??\PIPE` e
    `\??\MAILSLOT` vêm do `DOS Devices` do Session Manager: o smss os cria no
    boot dele, e no boot comum, sem smss, a fase 0 cria os mesmos links.
  - NtCreateNamedPipeFile e NtCreateMailslotFile capturam o
    NAMED_PIPE_CREATE_PARAMETERS/MAILSLOT_CREATE_PARAMETERS (timeout opcional
    com TimeoutSpecified; o mailslot com FILE_SHARE_READ | FILE_SHARE_WRITE e
    FILE_CREATE) e validam como o IopCreateFile valida um chamador de modo
    usuário; a abertura manda IRP_MJ_CREATE_NAMED_PIPE ou
    IRP_MJ_CREATE_MAILSLOT com os parâmetros na stack location. Toda
    abertura de modo usuário leva RequestorMode = UserMode e a thread que
    pede no IRP (o npfs.sys guarda o PID do cliente por ela).
  - NtReadFile/NtWriteFile de um arquivo de driver de neither I/O,
    NtFsControlFile (o IopXxxControlFile com IRP_MN_USER_FS_REQUEST, acesso
    do código conferido), o NtDeviceIoControlFile de um driver nativo com
    METHOD_IN_DIRECT, METHOD_OUT_DIRECT ou com evento (depois do
    FastIoDeviceControl; a entrada num SystemBuffer e a saída num MDL das
    páginas de usuário travadas, que a conclusão destrava e libera) e
    NtQueryInformationFile/NtSetInformationFile de qualquer arquivo de
    driver montam o IRP como o I/O Manager: Tail.Overlay.Thread,
    OriginalFileObject, UserMode, UserIosb, UserEvent, UserBuffer, o
    SystemBuffer do método e a IrpList da thread. A cauda síncrona espera
    FileObject->Event pelo KeWaitForSingleObject (a thread deixa a CPU) e
    devolve FileObject->FinalStatus; as consultas e mudanças num arquivo
    assíncrono esperam um evento e um IO_STATUS_BLOCK locais. A conclusão
    (IopCompleteRequest) roda na thread que pediu — na hora, se o driver
    conclui nela em PASSIVE_LEVEL, ou como APC especial de kernel entregue
    onde ela estiver —, copia o SystemBuffer para o UserBuffer
    (IRP_INPUT_OPERATION; o npfs.sys e o msfs.sys põem assim os dados de uma
    leitura que estava pendente), grava o IOSB, sinaliza o evento ou
    FileObject->Event, libera o IRP e solta o arquivo (a última referência,
    em PASSIVE_LEVEL). O IofCompleteRequest mantém Irp->PendingReturned como
    o NT, pelo SL_PENDING_RETURNED de cada slot, e num slot sem rotina de
    conclusão passa o SL_PENDING_RETURNED ao slot de cima (o IoMarkIrpPending
    que o IopfCompleteRequest faz no lugar da rotina). A saída de uma thread
    cancela as IRPs dela. As classes de acesso, modo, alinhamento e posição
    o próprio I/O Manager responde.
  - Teste: `ntos/test/multiprocess/pipes.rs` (fase 7): um servidor e um
    cliente reais em anel 3 com LISTEN, WAIT, PEEK, TRANSCEIVE, leitura e
    escrita em modo mensagem e byte (síncronas e assíncronas com evento), o
    PID do cliente, as classes de pipe, o mailslot e o DISCONNECT, com as
    esperas entre processos bloqueando de verdade.
- **Cadeia smss -> csrss real** (`--initial-process=smss`,
  `init/boot_config.rs::smss_boot`): o primeiro processo de usuário é o
  `\SystemRoot\System32\smss.exe` real (`init/initial_process.rs`), criado
  pelo caminho único com PS_PROTECTION WinTcb-Light (0x61) e
  BreakOnTermination, com a ntdll real. O build põe no volume os binários da
  cadeia (smss, csrss, csrsrv, basesrv, winsrv, sxssrv e as DLLs que eles
  importam; o npfs.sys e o msfs.sys, com os serviços Npfs e Msfs, vão em
  todo boot), e a hive SYSTEM desse build (ou a semente em
  memória, sem o arquivo) leva o Registro que eles leem: a
  chave Session Manager (`cm/session_manager.rs`: SubSystems com o Kmode e
  a linha do csrss, KnownDLLs, DOS Devices, Environment; sem BootExecute nem
  arquivos de paginação); a hive SOFTWARE desse build leva a
  árvore `IniFileMapping` que o basesrv lê
  (`cm/ini_file_mapping.rs`) e, na hive volátil HARDWARE, fica o
  `HARDWARE\DESCRIPTION\System\CentralProcessor\<n>` do CPUID
  (`cm/hw_description.rs`). Nesse boot ficam desligados a imitação do csrss
  (`ps/user/csr.rs`), a do gerenciador de serviços (`cm/service/rpc.rs`, o
  `\RPC Control\ntsvcs` e o `SvcctrlStartEvent_A3752DX`, que são do
  services.exe real), o `\KnownDlls` montado pelo kernel, o provisionamento
  de KnownDlls de `mm/section/open.rs` e o multi-sz de KnownDLLs que o
  kernel semeava: o próprio smss monta o `\KnownDlls`, os DosDevices,
  `\Sessions` e os prefixos protegidos dos pipes e mailslots. O smss é
  servidor ALPC: `alpc/server.rs` é o lado servidor das portas de usuário
  (NtAlpcCreatePort com nome, a conexão que espera a decisão do servidor no
  NtAlpcAcceptConnectPort, pedidos e respostas pelo MessageId,
  NtAlpcOpenSenderProcess/Thread), com o aviso na IOCP associada, que o
  thread pool da ntdll consome; o tick sonda as esperas de usuário paradas
  mesmo quando nenhuma thread de usuário está pronta
  (`ps/user/threads.rs::refresh_waiting`), porque o cliente que põe o pedido
  na fila do servidor para logo em seguida. O smss da sessão nasce por
  NtCreateUserProcess numa sessão nova, herda as seções do pai pelos
  mesmos valores, conecta-se ao `\SmApiPort` e cria o csrss.exe
  (protegido e crítico, ProcessBreakOnTermination em
  `ps/set_process_information.rs`; o fim de um processo crítico para a
  máquina com CRITICAL_PROCESS_DIED, `ps/critical.rs`). Serviços que essa
  cadeia pede e que
  moram no componente de cada um: NtAdjustPrivilegesToken
  (`se/token/adjust.rs`), NtSerializeBoot (`io/pnp.rs`), a
  ProcessSessionInformation, a SystemManufacturingInformation e a
  SystemSupportedProcessorArchitectures (`ex/`), NtCreateDirectoryObject,
  NtCreateSymbolicLinkObject, NtSetSecurityObject (também sobre os
  pseudo-handles de processo e thread), a ObjectSessionInformation (o
  SessionId do diretório, `ob/handle_attributes.rs`, também pelo
  ZwSetInformationObject) e a
  ObjectSessionObjectInformation do NtSetInformationObject, a duplicação
  de handles do Object Manager (com DUPLICATE_NO_RIGHTS_UPGRADE), a
  SystemTimeOfDayInformation (`ex/time_of_day_information.rs`, com o
  KeQueryBootTimeValues de `ke/clock.rs`), a ProcessLUIDDeviceMapsEnabled,
  o NtSetInformationVirtualMemory de modo usuário (as validações do serviço
  e a pré-busca, `mm/prefetch.rs`; a VmImageHotPatchInformation que a ntdll
  pede a cada DLL é STATUS_NOT_SUPPORTED, sem reserva de hot patch) e o
  NtFreeVirtualMemory do MmFreeVirtualMemory (`ps/user/memory.rs::free_in`:
  as recusas de FreeType, base e faixa, e o MEM_RELEASE de parte de uma
  região privada, que deixa o resto como região própria; o RtlCreateHeap
  de todo processo reserva o heap com uma folga aleatória e libera o começo
  dela). O marcador `SMSS_CSRSS_OK` sai
  quando uma thread do csrss.exe criado por um smss pede pela primeira vez
  um serviço da tabela do win32k (`ex/service_table.rs::out_of_range` ->
  `initial_process::win32k_requested`, antes da conversão em thread GUI)
  com o smss inicial e o csrss vivos: o csrss carrega o basesrv (diretórios
  `\BaseNamedObjects`, links e o mapeamento de .ini), o winsrv e o
  winsrvext, que importa o user32 real; a inicialização do user32 (com o
  kernelbase, o kernel32, o gdi32 e o gdi32full reais) chega ao NtGdiInit
  (serviço 0x12e3), o primeiro do win32k, que o win32k.sys real carregado
  pelo smss atende (veja o item seguinte).
  Com `OPENNT_TRACE_SYSCALLS`, as linhas `[sys]` dos serviços que abrem ou
  criam objetos por nome mostram o nome do OBJECT_ATTRIBUTES.
- **O win32k.sys real pelo smss** (`ex/system_information.rs`,
  `mm/sysload.rs`, `mm/session_image.rs`, `ps/win32.rs`,
  `po/power_information.rs`): no boot do smss o DXGKrnl tem o Start 1 da
  instalação (`cm/service/inbox_drivers.rs`) e sobe com os drivers de
  sistema, depois do `Control\GraphicsDrivers` (`cm/graphics_defaults.rs`),
  e o build põe no volume o win32k.sys, o win32kbase.sys, o win32kfull.sys,
  o hidparse.sys e o cdd.dll. O smss da sessão (o mestre da sessão 0) lê o
  `Kmode` e chama o NtSetSystemInformation(SystemExtendServiceTableInformation)
  com o SeLoadDriverPrivilege: o ramo de modo usuário sonda o buffer, exige
  o mestre de sessão (Vm.Flags.SessionMaster), o privilégio e exatamente
  `\SystemRoot\System32\win32k.sys`, e reentra pelo
  ZwSetSystemInformation(38) em KernelMode. O ramo de kernel carrega a
  imagem com LoadFlags 0x80000005 (imagem de sessão e compactação da
  W32pServiceTable, o MiCompactServiceTable) e chama o ponto de entrada com
  um DRIVER_OBJECT zerado (ExpInitializeSessionDriver); no sucesso, o
  MmSessionSetUnloadAddress grava o DriverUnload na sessão, que libera os
  callouts Win32 dela (MmSessionGetWin32Callouts: só processos de uma
  sessão com DriverUnload >= 2 usam o PsWin32CallBack). O DriverEntry do
  win32k resolve os contratos `ext-ms-win-*-win32k-*` pelo ApiSetMap da PEB
  do smss e carrega os hospedeiros com MmLoadSystemImage(0x80000001): o
  win32kbase.sys e o win32kfull.sys como imagens de sessão, o hidparse.sys
  antes pelo SystemLoadGdiDriverInSystemSpace (54) e solto pelo
  SystemUnloadGdiDriverInformation (27). O import de uma imagem já
  carregada pelo MmLoadSystemImage (o win32kfull importa do win32kbase e do
  hidparse) acha a entrada pela lista de imagens carregadas, como o
  MiResolveImageReferences, e retém o LoadCount dela; a imagem de sistema
  só sai quando ele zera. Cada sessão conta as cargas de uma imagem de
  sessão (o ImageCountInThisSession): a segunda carga na mesma sessão
  devolve sucesso sem LoadCount, e o MmUnloadSystemImage correspondente só
  desconta. O Win32kBaseDriverEntry cria `\Driver\Win32k`, conecta-se a
  `\Device\DxgKrnl`, publica a tabela 1 e a filtro (KeAddSystemServiceTable)
  e os callouts (PsEstablishWin32Callouts, pelo win32k.sys), e pede ao
  kernel o que o init do GDI e do USER usa: a seção nomeada
  `\Win32kCrossSessionGlobals` com OBJ_KERNEL_EXCLUSIVE (0x10000, aceito na
  captura dos atributos e no handle), PagedPoolSession com o bit NX
  (0x221), ExAllocatePoolWithQuotaTag de PagedPoolSession (a quota vai no
  bloco do heap da sessão e volta no free), o MmPageEntireDriver de uma
  imagem de sessão (só a DllBase), as listas LOOKASIDE_LIST_EX (o
  AllocateEx e o FreeEx recebem a lista) e o ZwPowerInformation de
  SessionPowerInit (41), SessionPowerCleanup (63), SystemVideoState (29),
  SessionRITState (61) e SessionConnectNotification (62).
  O marcador `WIN32K_LOADED` (`initial_process::session_driver_initialized`)
  sai quando o DriverEntry volta STATUS_SUCCESS com a tabela 1 do
  KeServiceDescriptorTableShadow e os callouts no lugar. Com
  `--trace-driver-api`, o DriverEntry do driver de sessão imprime cada
  export que chama, e depois do `SMSS_CSRSS_OK` todos os exports são
  impressos. O teste é o [[teste]] `win32k`. Depois do NtGdiInit o user32
  inicializa no csrss e o cfgmgr32.dll, que o winsrvext importa, abre o
  `\Device\DeviceApi\CMApi` no CMApiEntry (`io/pnp/device_api.rs`); o
  csrss usa o NtNotifyChangeKey (`cm/notify.rs`) e o NtQueryLicenseValue
  (`ex/license/values.rs::query_user`) de modo usuário, e o winsrvext
  chama o NtUserInitialize. Outros serviços que o smss e o csrss pedem no
  caminho, cada um no componente dono e com o handler de `ps/user` só
  ligando: o NtInitializeRegistry do smss (`cm/hive_init.rs`, cada etapa
  uma vez só: CM_BOOT_FLAG_SMSS, o aviso dos arquivos de paginação e o
  aceite do boot; as hives já foram ligadas na fase 1), o
  NtApphelpCacheControl da ntdll (`ps/apphelp_cache.rs`, o IOCTL ao
  `\Device\ahcache` ou, sem ele, o status pré-definido de cada serviço), o
  NtQueryDirectoryObject que o smss importa (`ob/handles/namespace.rs`,
  com as sondas de modo usuário, DIRECTORY_QUERY e as respostas do 19041
  para o fim da lista e a entrada que não cabe), o
  NtIsUILanguageComitted do csrss (`ps/locale.rs`; ele só passa a dar
  STATUS_SUCCESS depois do NtFlushInstallUILanguage com SetComittedFlag,
  que o winlogon faz depois de subir o dwm, com SeTcbPrivilege), as classes
  ProcessDefaultHardErrorMode e ProcessHandleCheckingMode do
  NtSet/NtQueryInformationProcess (`ps/set_process_information.rs`,
  `ps/query_process.rs`, com o ProbeForRead do alinhamento de cada classe),
  a ThreadBreakOnTermination do NtSetInformationThread
  (`ps/set_thread_information.rs`; a consulta dela e a da
  ProcessBreakOnTermination em `ps/query_thread.rs` e
  `ps/query_process.rs`) e as classes de tamanho fixo
  SystemFlagsInformation, SystemPhysicalMemoryInformation,
  SystemKernelDebuggerInformation (o KdDebuggerEnabled e o
  KdDebuggerNotPresent, sondagem de alinhamento 1) e
  SystemHypervisorSharedPageInformation do NtQuerySystemInformation
  (`ex/system_information.rs::query_fixed`, também no Zw). O NtCreateTimer,
  o NtOpenTimer (o ObOpenObjectByName com ExTimerObjectType), o NtSetTimer
  e o NtCancelTimer de modo usuário são adaptadores do ETIMER
  do Executive (`ex/timer_object.rs`, PreviousMode UserMode, em
  `ps/user/timer_objects.rs`). O NtCreateIRTimer é o NtCreateTimer2 com o
  atributo IR (2): o identificador IR passa pelo ExpCheckIRTimerAccess
  (`ex/ir_timer.rs`: índice de 1 a 15, sub até o máximo do ExpIRTimerDescs
  e o SID do serviço dono do índice na identidade, como o NT SERVICE\Power
  do índice 6 que o umpo pede) e o KeInitializeIRTimer grava o índice e o
  sub nos bytes 2 e 3 do Header do KTIMER2 (um sub que não fica abaixo do
  máximo é FAST_FAIL_INVALID_ARG); sem hardware de wake IR, o timer é um
  Timer2 comum e o NtSetIRTimer é o ExpSetTimer2 sem período (DueTime NULL
  cancela). O services.exe e o lsass pedem ainda as
  classes ProcessTimes (4), ProcessImageFileNameWin32 (43) e
  ProcessMitigationPolicy (52) do NtQueryInformationProcess
  (`ps/query_process.rs`), a ProcessRaiseUMExceptionOnInvalidHandleClose
  (71) do NtSetInformationProcess, a TokenMandatoryPolicy (27) do
  NtSetInformationToken, as classes SystemObjectSecurityMode (70),
  SystemIsolatedUserModeInformation (165), SystemFlushInformation (192) e
  SystemWriteConstraintInformation (195) do NtQuerySystemInformation, o
  NtQuerySystemEnvironmentValueEx (o privilégio antes do
  STATUS_NOT_IMPLEMENTED do firmware BIOS) e o NtUpdateWnfStateData e o
  NtCreateWnfStateName de modo usuário (`ex/wnf/service.rs`), todos como
  no 19041. O GlobalMemoryStatusEx do kernelbase faz três consultas: a
  SystemMemoryUsageInformation (182, a memória do banco de frames e o
  commit do sistema, `mm/memory_information.rs`), a ProcessQuotaLimits (1)
  e a ProcessVmCounters (3) (`ps/query_process.rs`, com o working set e o
  tamanho virtual tirados do VAD em `mm/process_usage.rs`); o total físico
  é o que o PFN enxerga, então o services.exe só separa os svchost quando
  isso passa do SvcHostSplitThresholdInKB. O `mm/process_usage.rs`
  recalcula esses valores nos campos do EPROCESS que o NT mantém
  (Vm.WorkingSetLeafSize, WorkingSetLeafPrivateSize, PeakWorkingSetSize,
  VirtualSize e PeakVirtualSize; as folhas presentes contadas pelas tabelas
  de páginas, `mm/paging::count_present_in`), e as duas consultas que os
  leem os recalculam antes: o MmQueryWorkingSetInformation da
  ProcessVmCounters e o ExpCopyProcessInfo da lista de processos. Também respondem como no 19041,
  cada uma no componente dono: a SystemCpuQuotaInformation (113,
  0xC00001A9 sem DFSS, `ps/session.rs`), a
  SystemEnergyEstimationConfigInformation (158, um BOOLEAN FALSE), a
  SystemPlatformBinaryInformation (133, STATUS_NOT_SUPPORTED sem tabela
  WPBT), a SystemMemoryTopologyInformation (138), a
  SystemCodeIntegrityPolicyInformation (164, pelo callback de política da
  CI, `se/code_integrity.rs`), a SystemShadowStackInformation (221, sem
  CET), a SystemPolicyInformation (134: exatamente 0x20 bytes, com 0x20 no
  ReturnLength; o pedido cifrado do slc passa pelo despachante do SPCall
  em `ex/license/system_policy.rs`, com a cifra em `policy_cipher.rs`: o
  código 0 lê o valor de licença pelo nome no armazém do convidado e faz a
  verificação de cópia genuína do kernel, o código 5 é a espera do
  trabalhador da marca d'água do explorer pela notificação de cópia não
  genuína, e os outros códigos respondem E_NOTIMPL como o tratador padrão
  do 19041; desvio: os códigos que o 19041 trata e que nada no convidado
  usa também caem nesse tratador), as classes 210 e 211 do NtQuerySystemInformationEx sobre o
  armazém de features vazio (`cm/feature_configuration.rs`), a
  ThreadIoPriority (22) do NtQuery/SetInformationThread e o
  TokenLinkedToken (19), que sem sessão irmã devolve
  STATUS_NO_SUCH_LOGON_SESSION. Num handle de dispositivo, o
  NtQueryVolumeInformationFile passa pelo I/O Manager
  (`io/file/irp_service.rs`): ele mesmo responde a FileFsDeviceInformation
  (o GetFileType de um pipe) e a FileFsDriverPathInformation, e manda as
  outras classes ao driver em IRP_MJ_QUERY_VOLUME_INFORMATION. Para a
  etapa da tela de logon também respondem como no 19041: a
  SystemRecommendedSharedDataAlignment (58, o KeLargestCacheLine; o
  CoreMessaging.dll encerra o processo por FailFast sem ela), a
  SystemSecureBootInformation (145, os dois BOOLEAN FALSE no boot BIOS), a
  ProcessPriorityClass de consulta (18, o GetPriorityClass do XAML), a
  ThreadCycleTime (23, o agendador de quadros do dwmcore), a
  ThreadNameInformation (38, o SetThreadDescription das threads do dwm,
  num bloco próprio no ETHREAD.ThreadName), a ProcessSubsystemProcess (68,
  só do processo mestre da sessão) e a ProcessEnergyTrackingState (82,
  STATUS_NOT_SUPPORTED sem o estimador de energia). A linha
  `[usermode] pid:tid X FALHOU` traz o chamador do stub da ntdll (o `[rsp]`
  do RSP de modo usuário que a entrada de syscall guarda na KPCR, como
  `módulo+deslocamento`), o nome da
  porta nas falhas de conexão ALPC/LPC (inclusive
  STATUS_OBJECT_NAME_NOT_FOUND) e o código das falhas de
  NtDeviceIoControlFile/NtFsControlFile. Um STATUS_ACCESS_DENIED ou
  STATUS_PRIVILEGE_NOT_HELD acrescenta ` negado: motivo tipo= pedido=
  concedido= falta= imagem=`: a primeira recusa anotada na chamada
  (`state::note_denial`: fora do tipo, DACL/integridade, privilégio, acesso
  do handle, duplicação além da origem, proteção do processo), as quatro
  primeiras por (pid, serviço, motivo, tipo) e depois uma a cada 64. A
  própria linha `FALHOU` sai nas quatro primeiras vezes de cada (pid,
  serviço, status, chamador) e depois uma a cada 256, com ` (N vezes)`, como
  a `[win32k] FALHOU`: a mesma falha do mesmo chamador é o padrão comum do
  Windows (o NtOpenThreadToken sem personificação, a sondagem de valores
  do Registro) e era metade dos 2,4 MB da serial do boot até a barra de
  tarefas, a uns 5 us por byte. A linha `classe N` das classes que o
  NtQueryInformationProcess não trata e a do NtQuerySystemInformationEx
  seguem a mesma regra por (serviço, classe). Com `--trace-failures`
  (TRACEFAILURES) sai toda falha e toda classe; com `--trace-files` (TRACEFILES), cada abertura de arquivo
  (`[usermode] arquivo aberto:`; a criação sai sempre) e cada consulta de
  atributos de um caminho ausente (`[file-io] attributes absent:`). O
  ProductPolicy do licenciamento é capturado quando a hive SYSTEM é ligada
  (o CmGetSystemControlValues, `cm/hive_init.rs`) e publicado logo depois,
  antes do primeiro driver (`init/phase1.rs`). O NtDeleteWnfStateName de um nome permanente ou persistente
  confere DELETE no descritor da definição (de modo usuário), apaga o valor
  dela na raiz do tempo de vida (ExpWnfDeletePermanentName) e a instância
  do nome em cada escopo do tipo dele (ExpWnfEnumerateScopeInstances,
  `ex/wnf/namespace.rs::next_scope_instance`), com o aviso de nome destruído
  aos assinantes: é o que o winlogon faz com o nome de prontidão do LogonUI
  a cada reinício dele. O autoteste `user_wnf_persistent` (fase 7) faz esse
  protocolo entre dois processos de usuário: criação do nome persistente
  com o descritor do winlogon, publicação, leitura e assinatura no outro
  processo, as duas entregas e a remoção. Os bits que o ProcessHandleCheckingMode e a ProcessRaiseUMExceptionOnInvalidHandleClose ligam valem como no 19041
  (`ob/handle_table.rs`): com EnableHandleExceptions, um handle não nulo
  que o ObReferenceObjectByHandle não resolve (o ExHandleLogBadReference)
  levanta STATUS_INVALID_HANDLE no anel 3 pelo KeRaiseUserException quando
  o PreviousMode da thread é UserMode, sem anexação e na tabela do processo
  dela; o NtClose de modo usuário de um handle desconhecido (fora de -6..0)
  só levanta com RaiseUMExceptionOnInvalidHandleClose também, ou com
  FLG_ENABLE_CLOSE_EXCEPTIONS ou a DebugPort do processo. A serial mostra
  `[ob] handle ... invalido ... levantado no anel 3`. Os serviços de usuário
  que procuram o handle na própria tabela (sem o ObReferenceObjectByHandle)
  ainda só devolvem o status. Autoteste em
  `ntos/test/multiprocess/handles.rs`. Um NtCreateKey com
  componente intermediário ausente devolve
  STATUS_OBJECT_NAME_NOT_FOUND, como o CmpDoParseKey: é o status que faz o
  kernelbase criar o caminho um componente de cada vez. Um serviço sem
  provedor nenhum (nem handler de usuário nem export) cai na falha comum da
  tabela nativa, que devolve STATUS_NOT_IMPLEMENTED sem passar pelo
  despacho; a entrada de syscall de usuário avisa uma vez por serviço
  (`[usermode] syscall X sem implementacao (sem provedor)`,
  `ex/system_services.rs::note_user_target`). A sessão do dxgkrnl
  (DpiSessionCreateCallback) espera o primeiro adaptador de vídeo
  iniciado, como no Windows: sem `--display=basic` o csrss fica ali. Com
  `--display=basic` o vídeo de boot do carregador
  (`bgk/graphics_information.rs`, o modo VBE pelo BIOS emulado) dá ao
  DxgkDdiStartDevice do BasicDisplay o framebuffer, o adaptador inicia
  (`ADAPTER_STARTED`, observado na interface de chegada de dispositivo de
  vídeo em `drivers/video/display_stack.rs`) e o InitVideo do win32k
  enumera o `\Device\Video0`. A sessão 0 é a de serviços
  (gbNonServiceSession falso): o InitVideo põe o gProtocolType em 0xFFFF e
  a configuração de exibição usa o dispositivo desconectado do win32k
  (`\Device\Disc`, DISPLAY_DEVICE_DISCONNECT), que o
  DrvSetDisconnectedGraphicsDevice cria pela chave
  `Services\TSDDD\Device0` da instalação (`cm/service/inbox_drivers.rs`);
  o BasicDisplay fica para a sessão do console. Pelo caminho o win32k pede
  ao kernel: o default do RtlQueryRegistryValues pelo próprio ponteiro
  DefaultData (`rtl/registry.rs`; a DrvDriverExtraCallback recebe
  DefaultLength 0x10000), o MmPrefetchVirtualAddresses de
  NtCurrentSession (`mm/prefetch.rs`), e, no xxxCreateThreadInfo de cada
  thread GUI, o ObSetHandleAttributes de UserMode e o
  ZwAssociateWaitCompletionPacket sobre handles da tabela do Object
  Manager (o evento do ZwCreateEvent e a IOCP e o evento duplicados como
  handles de kernel; `ob/handle_attributes.rs`, `ps/user/wait_packets.rs`)
  e o ObDuplicateObject com OBJ_KERNEL_HANDLE em KernelMode para a tabela
  do System. O NtUserInitialize do csrss volta com sucesso
  (`USER_INITIALIZED`); o winsrv pede ThreadBasePriority 2 para as threads
  dele (NtSetInformationThread, classes 2 e 3 como no NT; a
  ThreadBasicInformation devolve em BasePriority o mesmo incremento, o do
  KeQueryBasePriorityThread em `ke/thread_priority.rs`: 0 numa thread
  normal, Saturation * 16 numa saturada, que é o que o GetThreadPriority
  lê), o csrss assina
  os nomes WNF da instalação (`cm/wnf_defaults.rs`) e o sxssrv.dll lê a
  chave SideBySide (`cm/seed.rs`). Depois o CsrSbApiPortInitialize cria a
  porta LPC `\Windows\SbApiPort` (as portas LPC de modo usuário, no item
  seguinte), o smss mestre se conecta a ela e o SmpSbCreateSession pede ao
  csrss a sessão do wininit.exe: o csrss põe a `\Windows\ApiPort` como
  ProcessExceptionPort do processo novo, lê ThreadTimes e
  ThreadIsTerminated (NtQueryInformationThread) e retoma a thread; a
  ProcessDeviceMap do NtQueryInformationProcess dá as letras do `\??` do
  processo corrente (`ob/device_map.rs`). O wininit.exe conecta à
  `\Windows\ApiPort` (a ntdll pelo LPC, com PORT_VIEW, e o csrss, servidor
  ALPC, aceita com a vista), sobe a classe de prioridade
  (ProcessPriorityClass), registra o servidor RPC `\RPC Control\WMsgKRpc…`
  e, no CreatePrimaryTerminal do wininitext.dll, chama o
  RegisterLogonProcess: o win32kbase conecta ao WMsgKRpc pelo msrpc.sys
  (ZwAlpcConnectPort de uma thread de usuário dentro do serviço, que
  bloqueia como qualquer espera do ALPC; o contexto de segurança aberto
  numa thread de trabalho do System que impersona o cliente pela
  ThreadImpersonationToken da entrada Zw), e o servidor do rpcrt4 aceita o
  bind quando o TpCallbackMayRunLong (a classe 9 do
  NtSetInformationWorkerFactory) responde que a fábrica ainda cresce. No
  CreateWindowStationW, o user32 abre o arquivo do primeiro layout de
  teclado do `Keyboard Layout\Preload` do perfil do sistema (o kbdus.dll
  quando não há Preload) e o NtUserCreateWindowStation
  manda ao csrss um pedido síncrono de kernel direto à porta de conexão
  `\Windows\ApiPort` (`server::connection_request`). O idioma do convidado
  é o desta instalação (o xtask copia o `Control\Nls\Language`, o
  `Control\MUI\UILanguages`, o `Control\Keyboard Layouts`, o
  `Control\Keyboard Layout` e o perfil de idioma e de teclado da DEFAULT do
  Registro desta máquina, com o `Control Panel\Input Method` e os perfis
  de entrada do TSF de `Software\Microsoft\CTF`, põe no volume o `Layout File` dos layouts
  pré-carregados, como o KBDBR.DLL de uma instalação pt-BR, e os `.mui`
  dos programas nos idiomas de
  interface daqui, ou no idioma de fallback (o `DefaultFallback` do idioma
  e o `InstallLanguageFallback`, como o en-US) para um programa sem `.mui`
  neles; o kernel lê o `Control\Nls\Language` no boot,
  `ps/locale.rs`): os callbacks ao user32 do wininit acham o
  `<idioma>\USER32.dll.mui`. O ConvertHandleAndVerifyLoc do win32kbase
  confere o layout de teclado pelo nome do ObQueryNameString do
  FILE_OBJECT (a QueryNameProcedure do tipo File, `io/file/information.rs`,
  com o FileName do caminho da abertura) contra o `\SystemRoot\System32\`
  e o reabre pelo dispositivo (o alias de System32 do volume de boot vale
  também nessa abertura); o LoadFileContent lê o arquivo inteiro para o
  pool (o FileStandardInformation, até 256 KB, e um ZwReadFile do
  deslocamento 0), sem seção nem vista no espaço de sessão, e o
  ReadLayoutFile copia e reloca a seção `.data` do layout. O
  NtUserLoadKeyboardLayoutEx do LoadKeyboardLayoutW passa pelo mesmo
  caminho, e o NtUserCreateWindowStation devolve a WinSta0.
  O SetDefaultWinstaSecurity põe a DACL com o GenericMapping e o
  ValidAccessMask que o win32k gravou no TypeInfo do tipo WindowStation (o
  Ob lê o TypeInfo corrente, `ob/object_types.rs`), e o CreateDesktopW abre a
  Desktop Winlogon pela ParseProcedure da WinSta0. As mensagens que o
  xxxCreateDesktopEx do wininit e o xxxSwitchDesktop da RawInputThread do
  csrss mandam (xxxSetWindowPos -> xxxInterSendMsgEx) acordam a thread da
  Desktop do csrss pela porta de conclusão da fila de mensagens dela: o
  evento da fila alimenta, pelo pacote de espera, a IOCP que o
  LegacyInputDispatcher::WaitAndDispatch e o xxxRealSleepThread esperam
  direto no KeWaitForMultipleObjects (o corpo do IoCompletion é uma KQUEUE,
  `ob/objects/completion.rs`). O xxxCreateDisconnectDesktop cria a Desktop
  Disconnect e a abre no csrss com ObOpenObjectByPointer(0x1F0003) em
  KernelMode, que concede o pedido sem os direitos fora do ValidAccessMask
  do tipo, como o ObpCreateHandle (`ob/object_access.rs`); o DestroyDesktop
  termina em NUL o nome que o ObQueryNameString dá a uma Desktop (`\Nome`,
  fora do namespace, `ob/query_object.rs`). O wininit cria então a Desktop
  Default, chama o SwitchDesktop e o SetThreadDesktop e sobe o servidor RPC
  de pipe nomeado `\PIPE\InitShutdown` (a porta de conclusão e os modos de
  notificação de um arquivo de driver, `io/completion/file_port.rs`; os
  arquivos do volume de boot usam o mesmo FILE_OBJECT: as classes 30 e 41
  do NtSetInformationFile, o pacote do ApcContext no fim da leitura,
  escrita ou consulta de diretório e, sem porta, a APC de usuário da
  ApcRoutine, `ps/user/file_io.rs`). O
  CreateProcessW do services.exe chega ao NtCreateUserProcess com o bit
  0x200 que o kernelbase liga em toda criação sem CREATE_SUSPENDED (no
  19041 ele só escolhe o OwnerProcessId, `ps/create_context.rs`), e o
  BaseSrvCreateProcess do csrss lê a ProcessConsoleHostProcess (o
  OwnerProcessId) e a ProcessSequenceNumber do processo novo
  (`ps/user/syscalls_core.rs`). O CsrImpersonateClient do csrss impersona o
  wininit pelo NtImpersonateThread e o sxssrv.dll gera o contexto de
  ativação padrão do sistema com os manifestos de WinSxS que o xtask copia.
  O pool de threads do wininit espera o fim do services.exe por um pacote de
  espera sobre o processo, e o wininit cria o lsass.exe. O services.exe
  roda o SvcctrlMain: as proteções do ProcessMitigationPolicy, o
  ScGetPrivilege (NtDuplicateToken e NtPrivilegeCheck), o
  ScInitServiceConfigRoots e o ScInitDatabase com as chaves de serviço;
  depois espera o `LSA_RPC_SERVER_ACTIVE` do lsass, antes do início
  automático dos serviços. O lsass.exe pede a base de prioridade 9, abre o
  `\Security\LSA_AUTHENTICATION_INITIALIZED`, conecta ao Reference Monitor
  (`LSASS_STARTED`, o teste services), carrega o lsasrv.dll e as extensões e
  sobe as portas RPC `\RPC Control\lsapolicylookup` e
  `\RPC Control\lsasspirpc`. O SendRequestForNextAsyncKsecddCall deixa
  pendente no `\Device\KsecDD` o pedido METHOD_OUT_DIRECT 0x39006a (o
  ksecdd.sys o põe na fila CSQ dele), e o lsass cria o
  `LSA_RPC_SERVER_ACTIVE`. O services.exe acorda e chama o lsass pela ALPC
  (`\RPC Control\lsapolicylookup`, o LsaLookupOpenLocalPolicy e o
  LsaLookupGetDomainInfo do ScGetAccountDomainInfo). A chamada passa pela
  identidade do cliente (o ALPC_TOKEN_ATTR) e pelo NtAccessCheck do
  descritor da interface, e a resposta volta pelo envio adiado do worker
  factory. Com o LSA inicializado (o LsapStartLsa registra a extensão de
  consulta do lsasrv), o ScGetAccountDomainInfo passa e o SvcctrlMain
  segue: o ScEnableRpcInterface publica o `\RPC Control\ntsvcs` e o
  `\pipe\ntsvcs` (`SERVICES_STARTED`; a imitação do gerenciador de serviços
  do kernel fica desligada nesse boot), o servidor do SCE do scesrv.dll
  sobe o `\pipe\scerpc` e o InitWudfDriverManager carrega o
  WUDFPlatform.dll, lê a chave WUDF da SOFTWARE, cria um ETIMER de modo
  usuário (NtCreateTimer) e a porta ALPC
  `\UMDFCommunicationPorts\ProcessManagement`, no diretório que o kernel
  cria no IopCreateRootDirectories (`io/root_directories.rs`). O
  ScAutoStartServices acha no banco do SCM o DcomLaunch, o RpcEptMapper,
  o RpcSs e o LSM (início automático, com as chaves de serviço do Power,
  do BrokerInfrastructure e do SystemEventsBroker, que dividem o svchost
  do DcomLaunch, e o `Control\Power` copiados desta máquina, com "Desligar
  a tela: Nunca" no esquema ativo: o VIDEOIDLE e o VIDEOCONLOCK em zero, o
  que o powercfg grava, e a tela de logon não apaga durante o teste em
  qualquer máquina; o EnforceConsoleLockScreenTimeout desta máquina não vai
  ao convidado) e passa pelo
  logon de serviço: o ScLogonService pede ao lsass o LogonUserExExW da
  conta do serviço, e o LsapCreateTokenObject cria o token
  (NtCreateTokenEx) e grava nele a TokenMandatoryPolicy, a
  TokenAuditPolicy e a TokenOrigin (NtSetInformationToken 27, 16 e 17,
  `se/token/set_information.rs`). O CreateProcessAsUserW do
  CWin32ServiceRecord::LogonAndStartImage cria o svchost com o token no
  PS_ATTRIBUTE_TOKEN. O PspAllocateProcess (`ps/create_context.rs`) faz o
  RtlAcquirePrivilege, que basta com o SeAssignPrimaryTokenPrivilege no
  token primário de quem chama, mesmo desabilitado (o do SYSTEM, como no
  SeMakeSystemToken), ou aceita o token pelo SeIsTokenAssignableToProcess
  (`se/token/assignable.rs`: integridade dominada e token filho ou irmão do
  primário de quem chama). O svchost do DcomLaunch conecta ao `\PowerPort`
  do kernel (`po/umpo_channel.rs`, o PopUmpoInitializeChannel do
  PoInitSystem: um objeto Callback ligado à porta pelo NtAlpcSetInformation
  9 e chamado a cada mensagem posta na fila; o callback agenda um work item
  que trata as mensagens no processo System e aceita o primeiro cliente;
  os datagramas do umpo trazem os valores do esquema ativo
  (`po/power_setting.rs`)), sobe o endpoint `umpo` e pede o NtPowerInformation de modo usuário
  (`po/power_information.rs`: o PlatformInformation, o PlatformRole e o
  PowerInformationInternal 4). As definições WNF desta máquina
  (`Control\Notifications`), a ProductOptions e a ProfileList vêm do
  xtask; o ProductPolicy é o de uma instalação limpa e não ativada da
  edição (`xtask/src/product_policy.rs`: só as entradas das licenças PPD da
  edição, com os dados delas, e o estado de ativação de uma instalação
  nova não ativada, com o Security-SPP-GenuineLocalStatus 0 da cópia não
  genuína), e o NtGetCompleteWnfStateSubscription entrega ao modo usuário os
  callbacks WNF (`ex/wnf/notifications.rs`). O svchost do rpcss sobe o
  RpcEptMapper (`\RPC Control\epmapper`) e o RpcSs, que pede o
  NtPowerInformation 58 (o PowerSettingRegisterNotification do powrprof),
  e o services.exe inicia o LSM: o lsm.dll cria a
  `\SmSsWinStationApiPort`, abre a sessão (NtOpenSession) e registra a
  notificação de dispositivo no `\CMNotify`. Ali para: o
  SysNotifyStartServer do sysntfy.dll registra o endpoint no epmapper, e a
  conexão ALPC ao `\RPC Control\epmapper` confere o RequiredServerSid só
  contra o SYSTEM (o svchost do rpcss roda como NetworkService); o LSM
  falha e encerra os processos da sessão 1. O smss da
  sessão 1 cria o csrss e o winlogon.exe (o NtOpenSection relativo ao
  `\KnownDlls`, aberto pela tabela do Object Manager, e o powrprof.dll e o
  imm32.dll no volume); o NtUserInitialize do csrss da sessão 1 volta com
  sucesso. O RegisterLogonProcess do winlogon passa pelo
  LRPC_CASSOCIATION::OpenSecurityContext do msrpc.sys: o pacote vai para a
  IOCP do msrpc e acorda a única thread de trabalho dele, parada de novo no
  ZwRemoveIoCompletionEx depois de atender o wininit (ela sai da espera
  Ready; antes, o fim da espera de alertas a deixava Running fora da CPU).
  O winlogon abre então as Desktops Winlogon, Disconnect e Default da
  WinSta0 da sessão 1 e chama o NtUserSwitchDesktop (o xxxSwitchDesktop do
  win32kfull, depois do da RawInputThread do csrss da sessão 1, que entra
  pelo xxxCreateSystemThreads). Depois cria uma thread, carrega o kbdus.dll
  e o winsta.dll e para ali; nada é desenhado no framebuffer. Cada abertura
  de Desktop sai no log. A thread principal está no WinStationWaitForConnect
  do winsta.dll (g_WinlogonStage 0xe, evento WLEvt_WaitForLSM_Start): o
  WaitForLsmStart espera sem prazo o `Global\TermSrvReadyEvent`, que o
  winsrvext.dll do csrss cria (CreateTermSrvReadyEvent) e que o Local
  Session Manager (lsm.dll, num svchost criado pelo services.exe) sinaliza
  quando sobe; depois o winsta chama o LSM pelo RPC `ncalrpc:[LSMApi]`. A
  outra thread (LaunchUmfdHostWithVirtualAccountThreadProc) espera o LSA
  (WaitForLsa) antes de criar o fontdrvhost.exe. O vídeo da sessão 1 não
  espera o LSM: no 19041 o UserInitialize do win32kbase roda o InitVideo
  da primeira sessão interativa dentro do NtUserInitialize. O InitVideo
  abre o `\Device\Video0` do dxgkrnl, marca o dispositivo como WDDM (a
  lista de drivers dele vira "cdd") e o DrvSetDisplayConfig pede ao dxgkrnl
  os caminhos ativos (DxgkGetPathsModality) antes do hCreateHDEV, que
  carrega o cdd.dll pelo ZwSetSystemInformation(26) (a linha `[gdi]` do
  log). O cdd.dll pede ao dxgkrnl um adaptador de renderização, que o
  BasicRender.sys registra (o adaptador WARP em ROOT\BASICRENDER, com o
  dxgmms2.sys); além dele, a sessão 1 tem o dispositivo desconectado
  (`\Device\Disc`, TSDDD). O win32k põe o ponteiro do mouse no centro da
  tela e o BasicDisplay.sys o desenha direto no framebuffer: o primeiro
  pixel (`FIRST_PIXEL_OK`, teste primeiro-pixel). A Desktop do Winlogon é
  preta. O lsm.dll cria a porta ALPC
  `\SmSsWinStationApiPort` (o CCsrMgr, mensagens de 0x4070 bytes); o csrss
  de cada sessão cria o `Global\TermSrvReadyEvent`, o lsm o sinaliza, e o
  winsrvext.dll conecta à porta e manda um pedido síncrono cuja resposta é
  o próximo comando. O comando de conexão chega ao W32WinStationDoConnect:
  o NtUserRemoteConnect do win32kfull chama o xxxRemoteConnect do
  win32kbase, que no console só chama o GreDxgkSessionConnected (o
  InitVideo da sessão já rodou); o DxgkSessionConnected do dxgkrnl chama o
  DXGSESSIONMGR::SetConsoleSession e avisa o TTM, sem carregar nada (o
  callout de troca de tela só sai depois de uma mudança da política de
  energia HDR). O lsm exige o `Control\Terminal Server` e o
  `WinStations` (copiados desta máquina pelo xtask) e, depois da conexão
  do console, a definição do WNF_GPOL_SYSTEM_CHANGES
  (`cm/wnf_defaults.rs`), que o CPolicyMonitor assina; carrega o sysntfy.dll,
  o WMsgAPI.dll e o usermgrcli.dll, abre o `\KernelObjects\Session<id>` de
  cada sessão pelo NtOpenSession (`mm/session_object.rs`) e avisa as
  mudanças de estado pelo NtNotifyChangeSession
  (`io/session_notification.rs`: a IoStateSequence sob o evento de
  sincronização do MM_SESSION_SPACE, o IoState e o aviso ao
  IopSessionCallbackObject, síncrono para Created e Terminated e pelo
  IopSessionChangeWorker para os outros). O cdd.dll importa o
  KeSetActualBasePriorityThread, que troca a base absoluta da thread
  (`ke/thread_priority.rs`), e a RawInputThread pede a classe 82 do
  NtSetSystemInformation (SystemThreadPriorityClientIdInformation), que usa
  esse serviço. O winsrvext do csrss pede a classe 39
  (SystemPrioritySeperation) com o Win32PrioritySeparation de
  `Control\PriorityControl`: Length 4, o SeTcbPrivilege e o
  PsChangeQuantumTable (`ps/quantum.rs`), que escolhe a tabela de quantum
  do primeiro plano e dá a cada processo ativo o quantum do
  PspComputeQuantum (KeSetQuantumProcess). O RtlGetActiveConsoleId lê o ActiveConsoleId da
  KUSER_SHARED_DATA (`rtl/shared_data.rs`), que o win32k grava: 0 no
  DriverEntry da sessão 0, -1 quando o InitVideo dela fecha os dispositivos
  de vídeo e o id da primeira sessão interativa no DriverEntry dela (o
  CheckInitialSessions cria o `\UniqueInteractiveSessionIdEvent`); o
  watchdog (SMgrGetConsoleSessionId) e o dxgkrnl leem esse valor. O marcador `WINSTA0_OK`
  (`initial_process::desktop_opened`) sai quando o wininit.exe tem as
  Desktops Winlogon e Default da WinSta0, abertas pela ParseProcedure da
  WindowStation, e o `WINLOGON_DESKTOPS_OK` quando o winlogon.exe da sessão
  1 tem as dele (o teste winlogon).
- **Lista de processos** (`ps/system_process_information.rs`): o
  ExpGetProcessInformation do 19041 para a SystemProcessInformation (5), a
  SystemSessionProcessInformation (53), a SystemExtendedProcessInformation
  (57) e a SystemFullProcessInformation (148). Cada registro tem o
  SYSTEM_PROCESS_INFORMATION com os campos do EPROCESS que o
  ExpCopyProcessInfo copia (working set, privado, picos, faltas de página,
  tamanho virtual, cotas de pool, commit, handles pelo ExHandleTableQuery
  da tabela do processo, `ob/handle_table::query_handle_count`), os tempos,
  o CycleTime e os contadores de E/S do PsQueryStatisticsProcess
  (`ps/process_statistics.rs`), um registro de thread por thread viva (0x50
  na classe 5, 0x88 nas outras), a extensão de 0x170 bytes que o 19041 põe
  em todas as classes, o SID e a identidade de pacote na 148 e o nome da
  imagem do SeAuditProcessCreationInfo (só o último componente fora da
  148). O Gerenciador de Tarefas lê a classe 5; a coluna Memória é o
  WorkingSetPrivateSize. O autoteste `test/multiprocess/process_list.rs`
  confere a lista contra a ProcessVmCounters de um processo real parado e a
  forma das três classes.
- **As portas LPC de modo usuário** (`alpc/lpc_ports.rs` sobre
  `alpc/server.rs`, adaptadores em `ps/user/lpc.rs`): como no 19041, os
  serviços do LPC antigo são finos sobre o ALPC, e uma porta LPC é uma ALPC
  Port com o modo LPC (ALPC_PORFLG_LPC_MODE, 0x1000, no Flags dos
  atributos). NtCreatePort/NtCreateWaitablePort criam a porta de conexão do
  servidor de usuário (`create_legacy_port`: o MaxMessageLength até o
  LpcLegacyMaxMessageLength 0x288; MaxConnectionInfoLength e MaxPoolUsage
  não entram). NtConnectPort/NtSecureConnectPort capturam como o
  NtSecureConnectPort (PORT_VIEW de 0x30 bytes, REMOTE_PORT_VIEW de 0x18, o
  QOS e o SID exigido, conferido contra o usuário do token do dono da porta)
  e criam a porta do cliente com o modo LPC; a seção do PORT_VIEW é mapeada
  no cliente na conexão e no servidor quando ele recebe a mensagem de
  conexão pedindo o ALPC_MESSAGE_VIEW_ATTRIBUTE (o csrss, servidor ALPC da
  `\Windows\ApiPort`, aceita assim a conexão LPC da ntdll) ou a aceita com o
  REMOTE_PORT_VIEW (`server::ClientView`); a mensagem LPC_CONNECTION_REQUEST
  leva a informação de conexão e o ClientViewSize, e o cliente acorda com o
  handle, as bases da vista, o REMOTE_PORT_VIEW da seção do servidor e a
  informação da resposta. NtListenPort e NtReplyWaitReceivePort(Ex) recebem
  da fila da porta de conexão (pela porta de conexão ou pela de comunicação),
  com o PortContext da comunicação e, numa porta LPC, o Type sem os bits
  internos (máscara 0xC00F do AlpcpReceiveLegacyMessage: o servidor LPC vê
  LPC_REQUEST, não LPC_REQUEST|LPC_CONTINUATION_REQUIRED); NtReplyPort e a
  resposta do NtReplyWaitReceivePort respondem pelo MessageId.
  NtAcceptConnectPort acha a conexão sem a porta de conexão (o MessageId e o
  CLIENT_ID do PORT_MESSAGE, numa porta de conexão do processo corrente),
  cria a porta de comunicação com o PortContext e acorda o cliente;
  NtCompleteConnectPort só devolve STATUS_SUCCESS, como no 19041. Do lado do
  cliente, NtRequestWaitReplyPort e NtRequestPort usam o transporte ALPC do
  cliente (`ps/user/alpc.rs`: 0x20000 e 0x10000, com 0xC0000703/0xC0000701
  trocados por STATUS_PORT_DISCONNECTED/STATUS_LPC_REPLY_LOST); numa porta
  LPC, Type 0 é sempre um pedido novo, como no AlpcpSendMessage, então o
  MessageId e o CLIENT_ID que um buffer reaproveitado traz (o
  CsrClientCallServer manda a mensagem no buffer da resposta anterior) não
  contam. Do lado servidor, NtRequestPort e NtRequestWaitReplyPort são a
  mensagem nova do servidor (abaixo), e o NtReplyPort na porta de um
  cliente responde a uma mensagem que o servidor mandou a ele.
  NtImpersonateClientOfPort e NtAlpcImpersonateClientOfPort seguem o
  AlpcpImpersonateMessage: Flags acima de 15 ou MessageId zero dão
  STATUS_INVALID_PARAMETER, e os bits 2-3 pedem um nível que não pode passar
  do nível do contexto; a mensagem precisa já ter sido recebida e não trazer
  LPC_NO_IMPERSONATE (0x4000); com o contexto de segurança que o cliente
  mandou, o token dele (um contexto de rastreamento dinâmico, como o que o
  rpcrt4 manda nos pedidos assíncronos, retém o token efetivo da thread que
  o criou; um estático, uma cópia); senão a porta do cliente precisa de
  ALLOW_IMPERSONATION, e o rastreamento estático usa o contexto capturado na
  conexão (o NtConnectPort e o NtAlpcConnectPort de modo usuário capturam
  agora, como o AlpcpCreateClientPort), o dinâmico a thread que mandou e
  espera a resposta (SeCreateClientSecurity com o QOS da porta do cliente e
  SeImpersonateClientEx; uma mensagem assíncrona dá STATUS_ACCESS_DENIED);
  sem mensagem, o contexto estático da conexão. O NtAlpcConnectPort sem
  ALPC_PORT_ATTRIBUTES usa os atributos padrão do 19041 (ALLOW_IMPERSONATION,
  o QOS anônimo, dinâmico e só efetivo e MaxMessageLength 0x200); com eles,
  o MaxMessageLength da porta do cliente é o pedido (de 0x28 a 0xFFFF, senão
  STATUS_INVALID_PARAMETER) limitado ao da porta de conexão. As flags da
  conexão (de modo usuário e do ZwAlpcConnectPort) seguem o AlpcpConnectPort:
  só as altas contam; RELEASE_MESSAGE dá STATUS_INVALID_PARAMETER; a espera
  pela decisão do servidor é no modo anterior (UserMode com 0x100000) e
  alertável com 0x200000; a 0x80000 liga o ReturnExtendedInfo da porta do
  cliente, e numa recusa o PortContext que o servidor deu no
  NtAlpcAcceptConnectPort volta em *PortHandle junto com
  STATUS_PORT_CONNECTION_REFUSED (o UMPDC.dll conecta assim à `\PdcPort` e
  lê ali o motivo da recusa do pdc.sys). A mensagem de 32 bits
  (ALPC_MSGFLG_WOW64_CALL) não existe: STATUS_NOT_SUPPORTED, com registro.
  O autoteste `kwait` recusa uma conexão com e sem a 0x80000. O
  NtQueryInformationPort só confere o handle e zera o ReturnLength.
  NtReplyWaitReplyPort e as mensagens com PORT_DATA_INFORMATION
  (NtReadRequestData/NtWriteRequestData) não existem no transporte:
  STATUS_NOT_SUPPORTED, com registro. Em volta: NtRegisterThreadTerminatePort
  (`ps/termination_ports.rs`: o LPC_CLIENT_DIED com o CreateTime para cada
  porta registrada quando a thread termina), NtSetDefaultHardErrorPort
  (`ex/hard_error.rs`, só registra a porta) e a ProcessExceptionPort do
  NtSetInformationProcess (`ps/set_process_information.rs`), que o csrss põe
  em cada processo da sessão no CsrSbCreateSession. O autoteste
  `test/multiprocess/lpc_ports.rs` (marcador `LPC_PORTS_OK`, [[teste]]
  `lpc`) põe um servidor e um cliente de anel 3 conversando por todos esses
  serviços.
- **A impersonação entre threads** (`ps/security.rs`, adaptador em
  `ps/user/tokens.rs`): o NtImpersonateThread(ServerThread, ClientThread,
  SecurityQos) do 19041 copia o QOS de modo usuário (alinhado a 4, sem
  conferir o Length), referencia o handle do cliente com
  THREAD_DIRECT_IMPERSONATION antes do handle do servidor com
  THREAD_IMPERSONATE e faz o SeCreateClientSecurity do cliente e o
  SeImpersonateClientEx no servidor. É o CsrImpersonateClient do csrsrv.dll
  (o ThreadHandle da CSR_THREAD do TEB.CsrClientThread). O mesmo corpo serve
  ao NtAlpcImpersonateClientOfPort, com a thread corrente como servidora.
- **O que o services.exe e o lsass.exe pedem ao kernel ao iniciar**: o
  NtDuplicateToken de modo usuário (`ps/user/tokens.rs` sobre
  `se/token/duplicate.rs`; o RtlAcquirePrivilege da ntdll duplica o próprio
  token para ligar um privilégio, e o ScGetPrivilege do services.exe sai sem
  ele); a ProcessMitigationPolicy do processo corrente
  (`ps/mitigation_policy.rs`: ASLR, código dinâmico, verificação estrita
  de handles, chamadas de sistema, pontos de extensão, CFG, assinatura,
  fontes, carga de imagens, processos filhos, isolamento de canal lateral e
  confiança de redirecionamento, com as recusas do 19041; as de processos
  filhos e de redirecionamento ficam no TokenFlags do token primário, e o
  CFG, ausente em todo processo, recusa tudo como num processo sem CFG); a
  ProcessBasePriority
  (`ps/set_process_information.rs`); o pacote de espera sobre um processo
  (`ps/user/wait_packets.rs`: o pool de threads do wininit espera assim o
  fim do services.exe), que aceita qualquer objeto com objeto de espera de
  verdade (o `ob/wait.rs::wait_object_of`, com o FILE_OBJECT.Event de um
  arquivo) e recusa só mutant e fila (STATUS_INVALID_PARAMETER_3), como o
  19041; e o diretório `\Security` com o evento
  `LSA_AUTHENTICATION_INITIALIZED` do SepInitializationPhase1
  (`se/initialization.rs`), que o lsass.exe abre. Os dados vêm desta máquina
  no build: o contexto de ativação padrão do sistema, que o sxssrv.dll gera
  no primeiro CreateProcessW, precisa das chaves de SideBySide\Winners e dos
  manifestos de WinSxS do Microsoft.Windows.SystemCompatible e das
  dependências obrigatórias dele, e o contexto do LogonUI.exe, do dwm.exe e
  das DLLs da tela de logon com manifesto próprio pede o
  Microsoft.Windows.Common-Controls 6.0 (as chaves, os manifestos e os
  arquivos que eles listam, como o comctl32.dll da versão 6,
  `xtask/src/side_by_side.rs`) e, pelo <windowsSettings> (o dpiAware), os
  esquemas de configuração de SMI\WinSxs Settings; o services.exe lê as chaves de serviço da
  cadeia do LSM (DcomLaunch, RpcEptMapper, RpcSs e LSM), as do PlugPlay e
  do Power, que ele inicia pelo nome antes dos outros, e a do registrador
  do CoreMessaging (CoreMessagingRegistrar, que toda sessão CoreUI do
  dwm.exe e do LogonUI exige, com os `SecurityManager\TransientObjects` das
  portas dele) e a do serviço de política de vídeo (DispBrokerDesktopSvc,
  o servidor da classe WinRT DispBrokerDesktop.GlobalBrokerInstance que o
  uDWM do dwm.exe ativa na partida, com o grupo `LocalService` do
  svchost), o Control\ServiceGroupOrder, os valores EarlyStartServices
  e SvcHostSplitThresholdInKB de Control (o conjunto inicial e a separação
  dos serviços de um svchost) e os grupos do svchost
  (`xtask/src/user_services.rs`). O serviço do log de eventos (EventLog, o
  wevtsvc.dll no grupo `LocalServiceNetworkRestricted` do svchost) vem como
  numa instalação nova: a chave dele com o Parameters, o State e os canais
  clássicos com as fontes de eventos do Windows, os provedores e canais do
  Windows de `WINEVT` com o `WINEVT\Policies` vazio (o GroupPolicyManager
  do EventService::SecondPhaseInit o abre e, sem ele, o serviço para com
  ERROR_FILE_NOT_FOUND), as sessões de autologger EventLog-System,
  EventLog-Application e EventLog-Security com os provedores do Windows, e
  o `System32\winevt\Logs` vazio na raiz do volume, onde o modo usuário
  cria os `.evtx` (`xtask/src/event_log.rs`). Dos provedores, canais e
  fontes clássicas só entram os cujos arquivos de recursos e de mensagens o
  boot põe no volume (`windows_binaries::staged_image_names`): um provedor
  sem o binário no convidado não grava eventos, e a hive inteira fica no
  heap do kernel. O wevtsvc consome as sessões pelo tempo real do ETW
  (`etw/realtime.rs`). A tela de logon da sessão 1 leva o fecho
  de imports do dwm.exe e do LogonUI.exe com o XAML e os provedores de
  credencial (`LOGON_SCREEN_PROGRAMS` em `xtask/src/windows_binaries.rs`:
  com o que a thread de eventos do DWM cria no
  CDesktopManager::InitializeComObjects do uDWM, sem o que o dwm.exe não
  sobe, o UIAnimation.dll e o DispBroker.Desktop.dll; o ism.dll do
  anfitrião de entrada do CGlobalMit do dwmcore; o wuceffects.dll dos
  pincéis de efeito; o icu.dll da Calendar do relógio da tela de
  bloqueio; e o msftedit.dll da caixa de senha: o
  CTextBoxBase::InitializeTextServices do XAML cria nele o ITextServices2,
  e sem CoreWindow o WM_CHAR do TranslateMessage vai a esse
  ITextServices, sem o ctfmon nem o TextInputHost),
  os `.mun` e os `.pri` de `\Windows\SystemResources` desses programas (o
  imageres.dll.mun do bloco do usuário e dos ícones), os metadados WinRT de
  `System32\WinMetadata`, as imagens padrão da tela de bloqueio de
  `\Windows\Web\Screen`, os dados do ICU de `\Windows\Globalization\ICU` e
  o `timezones.xml` de `\Windows\Globalization\Time Zone`
  (`LOGON_SCREEN_FOLDERS`) e as do bloco do usuário
  de `%ProgramData%\Microsoft\User Account Pictures`, sem os `.dat` das
  contas desta máquina (`USER_ACCOUNT_PICTURES`), os perfis de usuário
  de uma instalação nova antes do primeiro logon
  (`xtask/src/user_profiles.rs`: `\Users` com o `desktop.ini`, o
  `Default` com a árvore de pastas, o `NTUSER.DAT`, o `.LOG1` e o
  `.LOG2`, e o `Public` só com as pastas conhecidas, cada pasta e
  arquivo com os atributos e o descritor desta máquina sem SID de
  conta; o DACL do `Public\Desktop` vem da definição da pasta conhecida
  e os filhos herdam de novo; nenhum perfil de conta nem arquivo com o
  SID, o caminho ou o nome de uma conta daqui, o nome do computador ou
  um endereço MAC dos adaptadores; as junções do perfil ficam
  listadas em `juncoes.txt` do build até o volume levar pontos de
  reanálise), a `ProfileList` com os diretórios de uma instalação nova,
  as definições das pastas conhecidas (`Explorer\FolderDescriptions`),
  o serviço de perfis (ProfSvc no `svchost -k netsvcs`, só com a conta
  LocalSystem, com o profsvc.dll e o profsvcext.dll no volume; o
  assinante `Profiles` vem com a chave `Control\Winlogon\Notifications`
  inteira; as chaves copiadas daqui perdem os SIDs de conta dos
  descritores, e um valor com SID de conta fica fora), o gerenciador de
  usuários (UserManager no `svchost -k netsvcs`, início automático depois
  do RpcSs e do ProfSvc, com o gatilho da interface RPC e sem `Security`,
  com o usermgr.dll e o UserMgrProxy.dll no volume, `user_services.rs`:
  com ele RUNNING o winlogon faz o logon pelo UMgrLogonUser e pede o
  sihost.exe pelo UMgrLaunchShellInfrastructureHost, e o svchost dele fica
  crítico), o StateRepository (no `svchost -k appmodel`, início sob
  demanda pela ativação das classes Windows.Internal.StateRepository.*,
  com o Windows.StateRepository.dll e o StateRepository.Core.dll no volume,
  a subchave `Svchost\appmodel`, o `PackageRepositoryRoot` e o
  `PackageRoot` de `Microsoft\Windows\CurrentVersion\Appx` e a pasta vazia
  `\ProgramData\Microsoft\Windows\AppRepository` dos bancos, nunca os
  bancos desta máquina), o registro dos pacotes da caixa no primeiro logon
  (`xtask/src/inbox_packages.rs`: as pastas do
  Microsoft.Windows.StartMenuExperienceHost e do ShellExperienceHost em
  `\Windows\SystemApps`, sem a `microsoft.system.package.metadata` que o
  AppXSvc gera; os serviços AppReadiness e AppXSvc com as DLLs deles; as
  chaves do AppX de uma instalação nova (a lista e o porquê em "Chaves do
  AppX que o xtask grava", abaixo), a classe COM e o AppID
  do AppReadiness, os SIPs do AppxSip.dll, o provedor
  WINTRUST_ACTION_GENERIC_VERIFY_V2 e as raízes públicas da Microsoft;
  o registro é dos serviços reais no convidado, e os bancos do
  StateRepository, os identificadores e o estado por usuário são todos
  feitos lá), as
  fontes de `\SystemRoot\Fonts` com o GRE_Initialize, o FontSubstitutes, o
  FontLink e a chave Fonts, e na SYSTEM o `Control\IDConfigDB` e os perfis
  de `Hardware Profiles` (o `LogPixels` do DPI, `xtask/src/fonts.rs`), o
  tema que o uxinit do winlogon carrega sem o serviço Themes (o
  `aero.msstyles` com o `.mui` e as chaves `ThemeManager` da SOFTWARE e da
  DEFAULT, `xtask/src/theme.rs`),
  o logon do usuário até a barra de tarefas e a área de trabalho (o
  userinit.exe com o userinitext.dll e o winlogonext.dll, o
  explorer.exe de `\Windows` com o `.mui`, na raiz do volume, o
  shell32.dll, o ExplorerFrame.dll da barra e o SndVolSSO.dll do ícone de
  volume, e o sihost.exe que o UserManager cria na sessão do usuário, com
  o Windows.Shell.ServiceHostBuilder.dll, o DesktopShellExt.dll, o
  fcon.dll da classe WinRT FeatureConfigurationsManager que o
  coordenador de rollout do DesktopShellExt ativa, os
  componentes que ele cria em processo, os imports estáticos deles e as
  cargas atrasadas de primeiro nível, porque um componente que falha
  derruba o sihost: `USER_LOGON_PROGRAMS` e `WINDOWS_PROGRAMS`; com eles o
  shell imersivo do twinui que o explorer sobe, com as DLLs dos
  componentes dele e das classes que eles ativam, porque um componente que
  falha também derruba o explorer), o papel de parede
  padrão do perfil Default (as imagens img0 de
  `\Windows\Web\Wallpaper\Windows` e de `\Windows\Web\4K\Wallpaper\Windows`,
  `WALLPAPER_FOLDERS`), as
  classes COM em processo (`Classes\CLSID`: o LogonUIController, os
  provedores de credencial, a fábrica e os codecs do WIC) e WinRT
  (`WindowsRuntime\ActivatableClassId`) das DLLs do volume, as classes
  WinRT fora de processo do DispBrokerDesktopSvc, do StateRepository, do
  UserManager e do WindowManagement com o `WindowsRuntime\Server` de cada
  um, as classes COM fora de processo que o explorer.exe e o sihost.exe
  registram, com o AppID delas (`SHELL_LOCAL_CLASSES`), sem os valores com o
  SID de uma conta (`S-1-5-21-...`) nos dados, as interfaces
  com o proxy numa dessas classes (`Classes\Interface`, menos as que o
  oleaut32 empacota pela biblioteca de tipos), com os
  provedores de `Authentication\Credential Providers` e o
  `Authentication\LogonUI` sem o último logon, o estado do boot nem os SIDs
  de usuário desta máquina, os `Time Zones` que a Calendar lê e os
  serviços de texto de `Microsoft\CTF` que o TSF em processo da caixa de
  senha lê, as associações do shell de uma instalação nova (`Folder`,
  `Directory`, `Drive`, `.exe`/`exefile`, `.com`, `.bat`, `.cmd`, `.txt`/
  `txtfile` e `.lnk`/`lnkfile`: só os verbos cujo DelegateExecute é uma
  classe copiada ou cujo comando abre o próprio arquivo ou um programa do
  volume, só os manipuladores de `shellex` de classes copiadas, sem as
  listas de OpenWith e sem valores com caminhos fora do Windows do
  convidado, e com os valores de uma instalação nova no open de `Folder`,
  dos programas e do `txtfile`; o que sai vai num AVISO) e as zonas de
  segurança (`Internet Settings\Zones`, as zonas do bloqueio da máquina
  local `Internet Settings\Lockdown_Zones` e os protocolos padrão do mapa de
  zonas, que o ZoneCheckUrlExW do ShellExecute consulta: o
  CUrlZoneManager::Initialize do urlmon liga um CRegZoneContainer para as
  `Zones` e outro para as `Lockdown_Zones`, e sem a segunda chave o
  primeiro InternetCreateZoneManager de cada processo falha, o
  MapUrlToZoneEx2Internal devolve E_UNEXPECTED e o ZoneCheckFile do
  windows.storage recusa o `.exe`, o que fazia o primeiro Executar de cada
  explorer.exe e o `launchtm.exe` do Ctrl+Shift+Esc falharem)
  (`xtask/src/logon_screen.rs`), e a chave `Microsoft\Windows\DWM`
  que o dwm.exe, o dwmcore e o dcomp leem e em que o dwminit grava a
  atividade de cada sessão (sem os `DwmInitSessionActivityId_*` desta
  máquina, `xtask/src/window_manager.rs`); a
  hive gerada põe uma chave com mais de 1012 subchaves em folhas sob uma
  raiz 'ri' (`xtask/src/hive_image.rs`), e cada chave leva o descritor de
  uma instalação nova: a raiz da SOFTWARE, da SYSTEM e da SAM com
  Usuários, Administradores, SYSTEM, CREATOR OWNER, ALL APPLICATION
  PACKAGES e a capacidade registryRead (na DEFAULT, os dois últimos só na
  raiz; a SECURITY só com SYSTEM e Administradores), as subchaves na
  forma herdada e, no boot do smss, o descritor próprio desta máquina das
  chaves que o têm protegido ou com ACEs explícitas (sem SID de conta),
  uma célula 'sk' por descritor distinto. A raiz do Registro do kernel
  (`cm/key/policy.rs`) é o CmpHiveRootSecurityDescriptor. A inicialização do LSA (o
  LsapInitLsa e o LsapStartLsa do lsasrv) pede ainda: o
  NtQueryInformationProcess das classes ProcessWow64Information (0) e
  ProcessProtectionInformation (o PS_PROTECTION do EPROCESS); os alarmes de
  auditoria de modo usuário (`ps/user/tokens.rs` sobre `se/audit.rs` e
  `se/access_check.rs`): NtPrivilegedServiceAuditAlarm,
  NtCloseObjectAuditAlarm e NtDeleteObjectAuditAlarm (sem GenerateOnClose,
  sucesso sem pedir privilégio), e o NtAccessCheckAndAuditAlarm e o
  NtAccessCheckByTypeAndAuditAlarm, todos com o SeAuditPrivilege do token
  primário (o SeCheckAuditPrivilege) e, nos dois últimos, o ClientToken e o
  nível de impersonação da thread (sem impersonação,
  STATUS_NO_IMPERSONATION_TOKEN; o token pode ser o primário do cliente);
  e as DLLs que o lsasrv carrega (os pacotes de segurança e as cargas
  atrasadas deles, `xtask/src/windows_binaries.rs`). O lsasrv levanta um
  erro grave (o LsapNotifyInitializationFinish) quando um desses passos
  falha. As hives SAM e SECURITY do convidado saem vazias, como as de um
  sistema novo (`cm/seed.rs`), e o lsass cria os bancos dele no primeiro
  boot: o samsrv só cria o banco de contas fora da instalação do Windows
  com o `Control\Lsa` `CreatePolicyDatabaseOnFirstBoot` diferente de zero
  (o SampSKUAllowsHiveCreation), que o xtask grava na chave do LSA copiada
  desta máquina. O RpcServerRegisterAuthInfo do lsass lê os provedores de
  autenticação do RPC em `SOFTWARE\Microsoft\Rpc\SecurityService`, também
  copiado. O marcador `LSA_POLICY_READY` sai quando o lsass publica o
  `\RPC Control\LSARPC_ENDPOINT` (o LsapRPCInit).
- **AlpcWaitForPortReferences** (`alpc/query_information.rs`, a classe 11
  do NtAlpcQueryInformation que o TpWaitForAlpcCompletion da ntdll pede ao
  desmontar um TP_ALPC): cada envio com o bit 18 (0x40000) das flags, de
  modo usuário, de modo kernel ou do trabalho adiado do worker factory,
  conta uma referência na porta (o ALPC_PORT.ReferenceNo); a consulta
  espera, alertável, o número dado, com um esperador por porta.
- **O RPC local entre o services.exe e o lsass.exe**: um pedido a um
  servidor ALPC de modo usuário (`alpc/server.rs`) chega com o MessageId do
  servidor. O NtAlpcQueryInformationMessage das classes de token
  (AlpcMessageSidInformation e AlpcMessageTokenModifiedIdInformation) acha
  esse pedido pelo MessageId e responde com o token efetivo da thread do
  cliente, que espera a resposta (`alpc/query_message.rs`). A recepção do
  servidor expõe o ALPC_TOKEN_ATTR (TokenId, AuthenticationId e ModifiedId
  desse token) quando o receptor aloca o ALPC_MESSAGE_TOKEN_ATTRIBUTE: é
  por ele que o I_RpcBindingInqClientTokenAttributes do rpcrt4 dá ao lsasrv
  a identidade do cliente. O descritor de segurança de uma interface RPC
  (RpcServerRegisterIf3) é conferido pelo AccessCheck do kernelbase, que é o
  NtAccessCheck (`se/access_check.rs::check_by_token`, adaptador em
  `ps/user/tokens.rs`): o token de impersonação do cliente, a DACL e o
  PRIVILEGE_SET de saída, como o SeAccessCheckByType do 19041. Sem ele,
  toda chamada ao `\RPC Control\lsapolicylookup` voltava ERROR_ACCESS_DENIED
  e o SvcctrlMain do services.exe saía pelo caminho de erro (que carrega o
  scesrv.dll para o ScesrvTerminateServer), antes do ScEnableRpcInterface.
  O NtAccessCheck captura o descritor numa cópia self-relative do kernel
  antes de validá-lo (o RtlValidSid do kernel recusa SIDs de usuário), e um
  pseudo-handle de token (o da thread ou o efetivo) não passa pela recusa de
  token primário, como no SepReferenceTokenUsingPseudoHandle. A resposta do
  servidor RPC sai pelo envio adiado do NtWaitForWorkViaWorkerFactory (o
  WORKER_FACTORY_DEFERRED_WORK: a mensagem, a porta e as flags altas, sem
  pedido síncrono), que manda a mensagem antes de esperar trabalho
  (`ps/user/alpc.rs::deferred_send`); quando a espera nem começa (handle
  inválido, fábrica encerrada, worker em excesso), a resposta sai na volta
  do serviço, com as flags inteiras. O envio só acontece com o bit 0 do
  Flags do bloco, como no 19041: o rpcrt4 deixa no bloco a mensagem do
  envio anterior e liga o bit só quando há resposta nova. Antes, a mensagem
  velha era reenviada a cada espera (STATUS_INVALID_PARAMETER ou
  STATUS_REPLY_MESSAGE_MISMATCH, e uma resposta velha podia chegar a um
  pedido novo com o mesmo MessageId).
- **O ALPC dos servidores de modo usuário** (`alpc/server.rs`,
  `alpc/message/view.rs`, adaptadores em `ps/user/alpc.rs`), no que o LRPC
  do rpcrt4 usa:
  - a associação da IOCP (NtAlpcSetInformation classe 2) posta um pacote
    para cada mensagem que já estava na fila da porta de conexão, como o
    AlpcpAssociateIoCompletionPort: o rpcrt4 cria a porta com nome antes de
    associar o pool, e uma conexão que chega nesse intervalo esperava para
    sempre;
  - o atributo de vista leva as mensagens grandes (pedidos acima de 0xF98
    bytes, respostas acima de 0xFC0): o envio acha a seção pelo handle e a
    vista pela base na porta de quem envia; a recepção mapeia a mesma região
    no processo de quem recebe, registrada na porta de conexão do servidor
    (ou na porta do cliente, para a resposta), que a apaga pelo
    NtAlpcDeleteSectionView; a resposta com UNMAP_EXISTING apaga a vista que
    o pedido trouxe ao servidor, e o reenvio da resposta recebida com
    UNMAP_EXISTING apaga a do cliente. NtAlpcDeleteSectionView e
    NtAlpcDeletePortSection existem em modo usuário;
  - a sequência do ALPC_CONTEXT_ATTR e do AlpcBasicInformation conta por
    porta de comunicação do servidor (pedidos, datagramas e o
    LPC_PORT_CLOSED do cliente; uma conexão conta na porta de conexão), que
    é o que o rpcrt4 compara para liberar a associação de um cliente que
    fechou;
  - o contexto de segurança e os handles do envio chegam ao servidor: o
    ALPC_SECURITY_ATTR com o ContextHandle do cliente, o ALPC_HANDLE_ATTR
    pelas regras da porta de comunicação (o Flags e o DupObjectTypes do
    NtAlpcAcceptConnectPort; com ALLOW_MULTIHANDLE_ATTRIBUTE, o número de
    handles e a classe 3 do NtAlpcQueryInformationMessage para cada um), o
    ALPC_TOKEN_ATTR e as classes de token pelo token do contexto, e o
    NtAlpcImpersonateClientOfPort impersona o token capturado no contexto;
  - os handles da resposta também chegam ao cliente (o AlpcpCaptureAttributes
    roda nas respostas, e o AlpcpExposeHandleAttribute na porta do
    cliente): o atributo de handles do envio do servidor é capturado do
    processo dele e fica com a resposta até o cliente recebê-la. Com
    ALLOW_MULTIHANDLE_ATTRIBUTE (a porta de cliente do rpcrt4, Flags
    0x2090000) a recepção traz {INDIRECT, Handle 0, ObjectType = o número de
    handles} e a mensagem continua resolvível pelo MessageId: a classe 3 do
    NtAlpcQueryInformationMessage duplica cada handle no cliente, até o
    reenvio da resposta sem flags e sem atributos (o DropMsgAttributes do
    rpcrt4) ou o fechamento da porta. Só com ALLOW_DUP_OBJECT a recepção
    traz o único handle já duplicado no cliente, e a mensagem sai. Um token
    entra no destino como os handles de token dele (a tabela de usuário de
    um processo comum, onde o NtQueryInformationToken os procura, ou um
    handle de kernel no System); uma chave do Cm (o CM_KEY_BODY da linha,
    descrito pelo dono das chaves de `cm/key/objects.rs`, código 0x100)
    entra como um handle interno novo da hive sobre o mesmo corpo
    (`key_services::insert_for`: na tabela de usuário, ou o handle de
    kernel do ZwOpenKey no System); os outros tipos, como linha do Object
    Manager. É o `[system_handle]` do RPC: o UMgrLogonUser do UserManager
    devolve assim o token do logon ao winlogon, o RpcGetUserToken do LSM
    o token da sessão ao DcomLaunch, e o services.exe a chave de estado do
    serviço ao GetServiceRegistryStateKey do sechost (o wevtsvc do
    EventLog pede a dele ao subir). A captura da resposta segue a do
    pedido: uma recusa com NTSTATUS recusa o envio;
  - todo pedido sem RELEASE_MESSAGE chega com LPC_CONTINUATION_REQUIRED
    (os assíncronos também), e a desconexão ou o fechamento da porta de
    comunicação pelo servidor termina com STATUS_PORT_DISCONNECTED os
    pedidos que o cliente espera e os envios seguintes dele;
  - a resposta que o servidor manda sem RELEASE_MESSAGE numa porta que não
    é LPC é também um pedido: o cliente a recebe como LPC_REQUEST com
    LPC_CONTINUATION_REQUIRED e pode respondê-la uma vez pelo MessageId dela
    (e o CallbackId, quando o cabeçalho traz um), com qualquer CLIENT_ID no
    buffer reaproveitado; a resposta
    segue ao servidor como pedido novo (LPC_REPLY se vier com
    RELEASE_MESSAGE). É o protocolo da `\SmSsWinStationApiPort`: o lsm.dll
    responde sem RELEASE_MESSAGE ao pedido do winsrvext do csrss com o
    próximo comando, e o csrss devolve o resultado respondendo a essa
    resposta com outro pedido síncrono;
  - a conexão sem ALPC_MSGFLG_SYNC_REQUEST não espera o servidor: o
    AlpcpProcessConnectionRequest do 19041 só chama o
    AlpcpReceiveSynchronousReply com esse bit (`bt r15d, 11h` em 0x5dee92) e
    volta com o status do AlpcpDispatchConnectionRequest, e o
    AlpcpConnectPort entrega o handle. Aqui o NtAlpcConnectPort(Ex) e o
    ZwAlpcConnectPort(Ex) põem a LPC_CONNECTION_REQUEST na fila
    (`Service::connect_deferred`, `UserServer::request_connection_deferred`)
    e voltam, sem tocar a mensagem de conexão nem os atributos de recepção;
    o NtAlpcAcceptConnectPort entrega a decisão dentro do accept
    (`server::decide`), e o LPC_CONNECTION_REPLY entra na porta do cliente
    com sequência 1 antes de qualquer mensagem que o servidor mande depois,
    avisando a IOCP ou o semáforo da porta esperável (no ZwAlpcConnectPort,
    pelo job da conexão e o pump). A recusa só libera a conexão, como o
    AlpcpAcceptConnectPort (ConnectionRefused na porta do cliente, nada na
    fila); o cliente que fecha a porta antes leva o pedido ainda não
    recebido, e o accept do que já foi recebido volta
    STATUS_PORT_DISCONNECTED. O CoreMessaging conecta assim e espera a
    resposta na porta: o MIT do dwm.exe (CGlobalMit::Run) e o servidor de
    navegação do sihost.exe conectam um ao outro ao mesmo tempo, e com a
    espera síncrona nenhum dos dois aceitava; o MIT parado deixava sem
    entrega os botões do mouse, que o win32kbase passa a ele
    (glDitMouseHandling, WakeDIT);
  - o RequiredServerSid do NtAlpcConnectPort e do NtSecureConnectPort é
    comparado com o usuário do token primário do dono da porta de conexão,
    que não pode ser AppContainer, e o descritor do NtAlpcConnectPortEx com
    o mesmo token (MAXIMUM_ALLOWED, e o concedido precisa incluir
    PORT_CONNECT); a recusa é STATUS_SERVER_SID_MISMATCH;
  - a segurança da porta segue o ObInsertObject: uma porta com nome exige
    DIRECTORY_CREATE_OBJECT no diretório pai (o nome relativo a um
    RootDirectory vale, inclusive o diretório de um namespace privado, pelo
    caminho ancorado nele, como nos outros tipos); sem descritor no
    OBJECT_ATTRIBUTES, recebe as ACEs herdáveis do pai (num `\RPC Control`,
    Everyone e RESTRICTED com PORT_CONNECT); a conexão de modo usuário (a
    do ALPC e a do NtConnectPort/NtSecureConnectPort legado) passa
    pelo SeAccessCheck de PORT_CONNECT contra o descritor atual da porta
    (STATUS_ACCESS_DENIED, com uma linha `[alpc] PORT_CONNECT ... recusado`
    no log);
  - as mensagens novas do lado servidor (`server::classify`, como o
    AlpcpSendMessage: numa porta LPC, ou no contrato LPC de kernel do
    LpcRequestPort e do LpcSendWaitReceivePort, o Type zero é uma mensagem
    nova e LPC_REQUEST com MessageId a resposta; nas outras portas o
    MessageId zero) seguem o AlpcpDispatchNewMessage. Na porta de conexão a
    mensagem vai à própria fila, com o PortContext e a sequência dela: é o
    que o dwm.exe faz com a DwmApiPort (o datagrama do SendSimpleAsyncRequest
    e o pedido síncrono do SendComplexSyncRequest, respondido pelo NtReplyPort
    da thread da porta) e o que o win32k faz pelo LpcRequestPort e pelo
    LpcSendWaitReceivePort. Numa porta de comunicação ela vai à porta do
    cliente (o callback do RPC), que precisa de ALLOW_LPC_REQUESTS
    (STATUS_LPC_REQUESTS_NOT_ALLOWED; o NtAlpcSetInformation classe 1 muda
    só esse bit, como o EnableCallbacksIfNecessary do rpcrt4 pede); o cliente
    a recebe entre as mensagens da porta dele, a IOCP dele avisada, e
    responde pelo MessageId. O datagrama (RELEASE_MESSAGE) não espera
    resposta; o envio síncrono espera o LPC_REPLY no buffer de recepção (o
    ALPC_CONTEXT_ATTR com o PortContext de quem enviou); sem as duas flags a
    resposta volta como LPC_REPLY na fila da porta de conexão. O Type
    conserva os bits altos do remetente (Type & 0xEF00 de modo kernel, &
    0x6F00 de modo usuário): o dwm.exe separa os comandos do win32k pelo
    LPC_KERNELMODE_MESSAGE (0x8000), e um pedido de modo usuário não o traz.
    A porta de conexão sempre tem ALLOW_LPC_REQUESTS, e a de comunicação do
    servidor nunca;
  - a porta esperável (NtCreateWaitablePort, ou WAITABLE_PORT nos atributos
    do NtAlpcCreatePort e do NtAlpcConnectPort(Ex) e do ZwAlpcConnectPort)
    tem o KSEMAPHORE do AlpcpInitializePort (contagem zero, limite
    0x7FFFFFFF, no corpo da porta): cada mensagem posta na fila dela sem IOCP
    associada (na porta de conexão, os pedidos, conexões e avisos; na do
    cliente, as respostas assíncronas, os cancelamentos e as mensagens do
    servidor) o libera uma vez, e a espera pelo handle da porta (o
    DefaultObject indireto 0xF9 do tipo ALPC Port: `ob/wait.rs` e o
    NtAssociateWaitCompletionPacket de `ps/user/wait_packets.rs`) fica nele.
    A thread da DwmApiPort espera assim antes de cada NtReplyWaitReceivePort,
    e o registrador do CoreMessaging e os clientes dele (portas 0x70000)
    esperam por pacotes de espera; nas outras portas o objeto de espera é o
    AlpcpDummyEvent, sinalizado, e a espera conclui de imediato;
  - a recepção comum (sem resposta síncrona nem mensagem direta) que acha a
    fila vazia segue o AlpcpReceiveMessagePort (`Port::empty_receive_status`
    em `ob/objects/port.rs`, nos caminhos do cliente e do servidor, de modo
    usuário e de kernel): com IOCP associada volta STATUS_UNSUCCESSFUL; na
    porta esperável, só o modo LPC espera (no semáforo) e as outras voltam
    STATUS_UNSUCCESSFUL; com objeto Callback volta STATUS_TIMEOUT; senão a
    thread espera. A recepção legada numa porta de comunicação do servidor
    segue as regras da porta de conexão. O CoreMessaging recebe sem prazo
    depois de cada espera pelo handle e para nesse STATUS_UNSUCCESSFUL;
  - a lista de conclusão (NtAlpcSetInformation classe 6) não existe: a
    classe recusa com STATUS_NOT_SUPPORTED numa porta de conexão (o rpcrt4
    solta o buffer e continua com a IOCP), e as classes 7, 8 e 10 respondem
    como sem lista registrada (sucesso, STATUS_INVALID_PARAMETER e
    STATUS_INVALID_PARAMETER); a classe 5 só confere o tamanho.
- **O rastro do LRPC** (`alpc/rpc_trace/`, `--trace-rpc`, a opção de carga
  TRACERPC): uma linha `[rpc]` na serial por mensagem que passa por uma
  porta de servidor (`alpc/server.rs`: a conexão e a decisão sobre ela, os
  envios do cliente, as respostas e as mensagens do servidor, o
  LPC_PORT_CLOSED e os datagramas de kernel), com o nome da porta de
  conexão, o pid do cliente e o do servidor, o Type, o MessageId, o
  ValidAttributes do envio e quais atributos chegaram com conteúdo
  (contexto de segurança, vista, handles). Nas portas do `\RPC Control` os
  dados seguem o formato LRPC do rpcrt4 19041 (`rpc_trace/lrpc.rs`, com os
  offsets lidos do LRPC_ADDRESS::ProcessIO, do
  LRPC_BASE_CCALL::InitializeRequestAndAttributes, do
  LRPC_SCALL::HandleRequest, do LRPC_CASSOCIATION::Bind e do
  LRPC_BASE_CCALL::UnpackResponse): o bind mostra a interface e a versão e
  guarda os contextos de apresentação da porta do cliente; o pedido mostra
  a interface do contexto que leva e o opnum; a resposta, a falha (o código
  de falha do RPC) e a resposta do bind mostram o pedido a que respondem,
  pelo MessageId. O rastro só observa; sem a opção, cada ponto de envio só
  lê a célula que o `boot_config::capture` preencheu.
- **O alarme das esperas em processos** (`ob/wait.rs`, sempre ligado): o
  services.exe dá um serviço como caído pelo IsProcessCrashed (um
  WaitForSingleObject de prazo zero no handle do svchost que o
  CreateProcessAsUserW devolveu), e o UpdateStartState então marca o
  serviço como falho e os dependentes não sobem (o UserManager depende do
  ProfSvc). Uma linha `[diag] espera satisfeita num processo vivo` sai
  quando uma espera de modo usuário (NtWaitForSingleObject,
  NtWaitForMultipleObjects) ou um pacote de espera é satisfeito num
  KPROCESS cujo processo não começou a terminar. Uma linha `[diag] espera
  satisfeita num handle de processo reaproveitado` sai quando o valor era
  um handle de processo do NtCreateUserProcess e hoje resolve para outro
  objeto sem que o dono o tenha fechado em modo usuário; ela traz quem
  fechou o valor (o fechamento passa por `ps/user/state.rs`). O alarme só
  observa.
- **Os tokens de logon** (`se/token/create.rs`, `se/token/set_information.rs`):
  o NtCreateToken e o NtCreateTokenEx do LSA (SeCreateTokenPrivilege
  habilitado, TokenType, o nível pelo QoS num token de impersonação, a sessão
  de logon criada pelo RmCreateLogonSession, dono e grupo primário entre o
  usuário e os grupos, a origem TOKEN_SOURCE e os atributos de segurança de
  usuário). Grupos e privilégios passam pelas regras do SepCreateTokenEx
  (`create.rs::shape`): grupos repetidos saem, os obrigatórios ficam
  habilitados, deny-only habilitado é recusado e deny-only liga
  TOKEN_IS_FILTERED, o dono precisa de SE_GROUP_OWNER, o SID S-1-16 acima de
  0x4000 é recusado e com SE_GROUP_INTEGRITY_ENABLED é o rótulo de
  integridade (sem ele, Untrusted), de Medium para cima o token tem
  TOKEN_NOT_LOW, e abaixo de High os privilégios fora da máscara do LUA
  nascem desligados; privilégios repetidos, desconhecidos ou com atributos
  inválidos são recusados. Os SIDs de serviço que o services.exe pede para o
  svchost entram como os outros grupos, com os atributos pedidos. O
  NtSetInformationToken trata as classes TokenOwner, TokenPrimaryGroup,
  TokenDefaultDacl, TokenSessionId (o SeSetSessionIdToken: o LSA grava a
  sessão do cliente do LsaLogonUser, a do winlogon para as contas DWM-n e
  UMFD-n; recusada no token de um processo vivo) e TokenSecurityAttributes
  (as operações ADD, DELETE, REPLACE e REPLACE_ALL), com a máscara de
  classes e os acessos do 19041. O TokenSessionReference (só o valor 0, com o SeTcbPrivilege) faz
  o token largar a sessão de logon (TOKEN_SESSION_NOT_REFERENCED em
  TokenFlags): o LsapSetSessionToken do lsasrv faz isso com o token de cada
  sessão que guarda, e o RmDeleteLogonSession não conta esse token. O
  TokenIntegrityLevel troca o nível do SID de integridade do token (subir
  pede o SeTcbPrivilege e um token sem uso; abaixo de High e de Medium os
  privilégios fora das máscaras do 19041 ficam desligados, mas presentes):
  o dwminit do winlogon sobe assim o token da conta DWM-n para System. O
  TokenPrivateNameSpace (o usermgr, com o SeTcbPrivilege) liga
  TOKEN_PRIVATE_NAMESPACE. O rótulo de integridade fica à parte no
  registro do token (`integrity`), mas com o lugar e os atributos que tinha
  entre os grupos (`label_index`, `label_attributes`): o TokenGroups, o
  TokenAccessInformation, o GroupCount do TOKEN_STATISTICS e o
  TokenIntegrityLevel o mostram como o UserAndGroups do NT, e o
  SepMakeTokenEffectiveOnly o move com os outros grupos. O TokenLogonSid
  devolve o grupo SE_GROUP_LOGON_ID (ou STATUS_NOT_FOUND). O CreateProcessAsUser passa o token no PS_ATTRIBUTE_TOKEN do
  NtCreateUserProcess. Todo processo novo recebe como token primário o
  SeSubProcessToken (`tokens::sub_process_token`) do token pedido ou, sem
  ele, do primário do pai declarado (ou de quem cria): uma cópia com o
  TokenFlags da origem (o SepDuplicateToken, que toda cópia de token segue),
  o dono padrão, o ModifiedId e o SessionId da sessão do processo. O
  descritor dessa cópia é o do ObInsertObjectEx sem descritor explícito,
  com o TOKEN_QUERY de BUILTIN\Administrators do SepFinalizeTokenAcls: com
  o token pedido, o dono e a DACL padrão do próprio token (a que o
  services.exe põe no token de um svchost dá ao SYSTEM do DcomLaunch o
  token de NetworkService do svchost do RPCSS); com o do pai, os de quem
  cria. Quem
  cria precisa do SeAssignPrimaryTokenPrivilege habilitado no token efetivo
  ou de um token atribuível; um token de outra sessão que a de quem cria
  exige o privilégio e leva o processo à sessão do token (o
  PspAttachSession, `mm::session::join_id`).
- **Tokens restritos** (`se/token/filter.rs`, `se/capture.rs`): o
  NtFilterToken de modo usuário (o CreateRestrictedToken da kernelbase)
  captura SidsToDisable, PrivilegesToDelete e RestrictedSids com o
  SeCaptureSidAndAttributesArray e o SeCaptureLuidAndAttributesArray,
  referencia o token com TOKEN_DUPLICATE e passa pelo mesmo SepFilterToken
  do SeFilterToken. O token novo recebe o descritor do SeAssignSecurity de
  quem chama (com o TOKEN_QUERY de Administrators) e um handle com o acesso
  do handle de origem. O dwminit do winlogon tira assim os privilégios do
  token da conta DWM-n, e o services.exe faz o token WRITE_RESTRICTED dos
  serviços de SID restrito.
- **O par de tokens do UAC** (`se/token/elevation.rs`, `se/logon_session.rs`,
  `ps/boot_phase.rs`): o TokenElevation é o do ntoskrnl 19041 (algum dos
  privilégios de 0x11_2016_0684 presente, ou o usuário ou um grupo com RID
  elevado pelo RtlIsElevatedRid), e o TokenElevationType sai dos Flags da
  sessão de logon do token (4 Limited, 2 Full, senão Default). Com o UAC
  ligado, o LsapBuildAndCreateToken do lsass divide um logon interativo
  elevado: cria uma segunda sessão e um segundo token, filtra-o
  (NtFilterToken com LUA_TOKEN), liga TokenVirtualizationAllowed (23, com o
  SeCreateTokenPrivilege) nele e chama o TokenLinkedToken (19) do
  NtSetInformationToken no token completo. Esse é o SepLinkLogonSessions:
  cada sessão guarda uma cópia primária do seu token (que deixa de
  referenciar a sessão) e o LogonId da outra, a completa ganha o Flags 2 e
  uma referência a mais, que a filtrada (Flags 4) solta quando sai. O
  TokenLinkedToken do NtQueryInformationToken devolve um handle para uma
  cópia do token da sessão irmã: primária com o SeTcbPrivilege de quem
  consulta, senão de impersonação em SecurityIdentification. O
  TokenVirtualizationEnabled (24) só liga num token com
  VIRTUALIZE_ALLOWED; o TokenUIAccess (26) pede o SeTcbPrivilege para
  ligar. Os bits de UAC da KUSER_SHARED_DATA (DbgElevationEnabled,
  DbgVirtEnabled, DbgInstallerDetectEnabled) vêm do PsBootPhaseComplete, no
  fim do NtInitializeRegistry do smss: só com
  `Control\LsaInformation\UACInstalled`, e cada um ligado a não ser que o
  valor de `Policies\System` seja um REG_DWORD 0. As hives do xtask não têm o
  UACInstalled, então o UAC fica desligado (o lsass também lê o
  UACInstalled); a virtualização de Registro e de arquivos dos tokens com
  VIRTUALIZE_ENABLED não existe.
- **O servidor de comandos do Reference Monitor** (`se/reference_monitor.rs`
  sobre o lado servidor LPC de modo kernel de `alpc/lpc.rs`): o
  SeRmInitPhase1 cria a porta LPC `\SeRmCommandPort` (ZwCreatePort,
  MaxMessageLength 0x200) e a thread de sistema do SepRmCommandServerThread
  antes do primeiro processo de usuário. A thread repete o
  ZwReplyWaitReceivePort (a resposta do comando anterior e a próxima
  mensagem, numa espera de kernel sem prazo). O lsass.exe conecta no
  LsapRmInitializeServer: o SepRmLsaConnectRequest abre o processo dele pelo
  CLIENT_ID da mensagem, aceita com o PortContext do silo hospedeiro e o
  REMOTE_PORT_VIEW (ZwAcceptConnectPort e ZwCompleteConnectPort) e conecta de
  volta à `\SeLsaCommandPort` do lsass (ZwSecureConnectPort com o QOS de
  impersonação dinâmica), que precisa devolver o MaxMessageLength 0x200; um
  segundo LSA é recusado. O estado é a SEP_RM_LSA_CONNECTION_STATE dos
  símbolos. Os comandos RM_COMMAND_MESSAGE (`inc/types/extra_obpsse.rs`) de 1
  a 12 vão à tabela SepRmCommandDispatch, que grava o ReturnedStatus na
  resposta: o RmAuditSetCommand põe a política de auditoria
  (`se/audit.rs::set_policy_from_lsa`, o SepRmSetAuditEventWrkr com o código
  1/2/4 por categoria), e o RmCreateLogonSession e o RmDeleteLogonSession
  criam e apagam sessões de logon (`se/logon_session.rs`, com
  STATUS_LOGON_SESSION_COLLISION e STATUS_BAD_LOGON_SESSION_STATE como no
  NT). O comando 4 grava o AccountName e o AuthorityName da sessão (o
  SepUpdateLogonSessionTrack). O comando 5 instala a SACL global de um tipo
  de objeto (`audit::set_global_sacl_from_lsa`, o SepRmGlobalSaclSetWrkr):
  o valor padrão de `SECURITY\Policy\GlobalSaclName<tipo>`; sem a chave, a
  resposta é STATUS_OBJECT_NAME_NOT_FOUND, que o LsapAdtInitialize do
  lsasrv aceita. O comando 7 liga a auditoria da linha de comando. Os
  comandos 6 e 8 a 12 respondem STATUS_NOT_SUPPORTED, com registro (o 6, as
  políticas de acesso central, é o LsapApplyCAPsUpdate, cuja falha o lsasrv
  só registra). O RmAuditSetCommand e o comando 7 ligam o
  SepRmAuditingEnabled; o SeRmInitPhase1 registra a auditoria no ETW (o
  SepAdtInitializeAuditingOptions: o AdtpRegisteredWithEtw e o evento
  `\ADT_ETW_CHANNEL_INIT` sinalizado). Quando a conexão do lsass fecha, o
  Reference Monitor zera o SepRmAuditingEnabled, esvazia a fila do aviso de
  sessão apagada, fecha a `\SeRmCommandPort` e encerra a thread, como no
  silo hospedeiro do NT. A conexão de volta ainda não leva o PORT_VIEW de
  4 KB do NT (o ZwSecureConnectPort de kernel não monta vistas). O lado
  servidor LPC de modo kernel são o ZwCreatePort, o ZwReplyWaitReceivePort
  (a recepção legada com o PortContext,
  `server::begin_kernel_legacy_receive`), o ZwAcceptConnectPort (o
  `server::accept_legacy` em KernelMode) e o ZwCompleteConnectPort; o
  autoteste `test/kernel_waits.rs` põe um servidor e um cliente LPC de kernel
  em threads de sistema.
- **O aviso de sessão de logon apagada ao LSA** (`se/lsa_call.rs`, o
  SepRmCallLsa): quando o último token de uma sessão de logon sai, o
  SepDeReferenceLogonSession (`se/logon_session.rs`) põe um SEP_WORK_ITEM
  (`inc/types/extra_obpsse.rs`) com o comando 3 e o LUID na fila
  SepLsaDeletedLogonQueueInfo (o SepInformLsaOfDeletedLogon); a sessão que o
  LSA apaga pelo RmDeleteLogonSession não volta a ele. A fila numera os
  itens e, quando passa de vazia a um item, põe o trabalhador SepRmCallLsa
  na DelayedWorkQueue. O trabalhador espera o `\ADT_ETW_CHANNEL_INIT`
  enquanto a auditoria não está registrada no ETW e só manda os itens com o
  SepRmAuditingEnabled; o SepRmDispatchDataToLsa monta a LSA_COMMAND_MESSAGE
  (TotalLength 0x38, DataLength 0x10, CommandNumber 3, parâmetros imediatos,
  o LUID em +0x30) e a manda como datagrama pelo ZwRequestPort
  (`alpc/lpc.rs::request_port_by_handle`) na conexão de volta à
  `\SeLsaCommandPort`. O lsass entrega o comando 3 ao lsasrv, que apaga a
  sessão da tabela de sessões de logon do LSA; os pacotes de segurança, o
  cofre de credenciais e o DPAPI recebem o fim da sessão. Sem o aviso, as
  sessões de cada logoff de usuário e das contas virtuais DWM-n e UMFD-n
  ficariam vivas no LSA. Os outros tipos de memória e os comandos com
  resposta (os registros de auditoria do NT) não existem; o autoteste
  `test/lsa_logon_notice.rs` cobre o datagrama num par LPC de kernel, o
  portão do ETW, o esvaziamento e o gancho da sessão de logon.
- **Os últimos exports da família win32k e dos drivers de console, PCI,
  ACPI e rede**, cada um no componente dono:
  - o objeto Timer (ETIMER) em `ex/timer_object.rs`: NtCreateTimer,
    NtSetTimer e NtCancelTimer com o modo anterior como parâmetro (os Zw*
    em KernelMode), o corpo de 0x148 bytes do ObCreateObjectEx com
    ExTimerObjectType, a TimerApcRoutine pela KAPC embutida (KernelRoutine
    ExpTimerApcRoutine, entregue na thread que armou, com a hora do sistema),
    o período refeito pelo DPC interno, a DeleteProcedure ExpDeleteTimer e o
    ExTimerRundown na saída da thread (a ActiveTimerListHead do ETHREAD);
    ExpTimerApcRoutine, ExpDeleteTimer e PspIoMiniPacketCallbackRoutine são
    rotinas privadas (`init/exports.rs::private_routines`); o NtQueryTimer
    (só ETIMER: RemainingTime = KeQueryTimerDueTime menos o tempo de
    interrupção, TimerState = o SignalState); o NtSetTimerEx de todo
    SetWaitableTimer(Ex) (a classe TimerSetCoalescableTimer, 0x30 bytes
    capturados, Period acima de MAXLONG dá STATUS_INVALID_PARAMETER_3; o
    handle referenciado sem tipo vai ao ExpSetTimerObject com o
    TolerableDelay num ETIMER, ao ExpSetTimerObject2 num IRTimer, que não
    aceita APC, WakeContext, TolerableDelay nem PreviousState, e dá
    STATUS_OBJECT_TYPE_MISMATCH em outro tipo);
  - o objeto IRTimer do NtCreateTimer2 em `ex/ir_timer.rs`: tipo "IRTimer"
    próprio (o ETIMER e o IRTimer não se confundem no
    ObReferenceObjectByHandle), corpo de 0xA8 bytes com o KTIMER2 de
    `ke/timer2.rs` no início (o objeto de espera), sem nome
    (ObjectAttributes dá STATUS_INVALID_PARAMETER_3), as recusas do
    ExpExTimerAttributesAreValid (STATUS_INVALID_PARAMETER_4) e de Reserved
    sem IR (STATUS_INVALID_PARAMETER_2), HIGH_RESOLUTION aceito e IR pelo
    ExpCheckIRTimerAccess (o NtCreateIRTimer, acima; o timer IR leva o
    TypeFlags IdleResilient e recusa período); o NtSetTimer2/NtCancelTimer2 pelo
    ExpSetTimerObject2 (KeSetTimer2: prazo relativo sobre o tempo de
    interrupção, não sobre a hora do sistema; T2_SET_PARAMETERS inválido dá
    STATUS_INVALID_PARAMETER_3) e o vencimento pelo pump dos timers do Ke;
  - os objetos de reserva em `ps/memory_reserve.rs` (UserApcReserve e
    IoCompletionReserve, NtAllocateReserveObject também de modo usuário),
    com o pacote embutido que o NtSetIoCompletionEx/ZwSetIoCompletionEx
    publica (`io/completion/set.rs`) e a retirada devolve, e a KAPC embutida
    que o NtQueueApcThreadEx(2) com handle de reserva enfileira
    (`ps/user/user_apc.rs`; o PspUserApcReserveRundownRoutine devolve a
    reserva na entrega ou no rundown);
  - NtQuerySystemInformationEx de modo kernel em `ex/system_information.rs`
    (classes 107, 121 e 180, com o KeNodeDistance e o steering de
    interrupções de `ke/`; 8 com o grupo da entrada e 175, os conjuntos de
    CPU de `ke/cpu_set.rs`; de modo usuário, a entrada obrigatória, só as
    classes com entrada e a sonda com o alinhamento de cada uma), as classes
    8 (o tempo de kernel e de usuário que `ps::process::account_thread`
    cobra de cada processador, com o ocioso no resto), 76 (as tabelas de
    firmware nos dois modos) do NtQuerySystemInformation, as classes 56
    (a validação do PfSnSetPrefetcherInformation em `pf/`, com os cenários
    do prefetcher desligados) e 177 (o callout Win32 do WER para o processo
    numa sessão) do NtSetSystemInformation nos dois modos,
    PsChargeProcessPoolQuota/PsReturnPoolQuota em
    `ps/pool_quota.rs`, ZwSetInformationProcess (ProcessBreakOnTermination e
    ProcessDebugFlags, as mesmas rotinas do NtSetInformationProcess de
    usuário) e a consulta de ProcessDebugFlags em `ps/`, e
    ZwQueryWnfStateNameInformation em `ex/wnf/query.rs`;
  - o lado servidor de modo kernel do ALPC (`alpc/server.rs`:
    ZwAlpcCreatePort, ZwAlpcAcceptConnectPort e a recepção do
    ZwAlpcSendWaitReceivePort pela continuação de kernel) e o LPC de modo
    kernel sobre ele (`alpc/lpc.rs`: LpcRequestPort, LpcSendWaitReceivePort
    e ZwSecureConnectPort, sem as vistas de seção do LPC, e o lado servidor
    do Reference Monitor, no item dele);
  - a abertura de kernel de um nome dentro de um dispositivo sem volume e a
    abertura relativa a um handle de arquivo de dispositivo
    (`io/file/zw.rs`, `io/io_manager.rs::open_related_device_file`), com a
    thread que abre no IRP_MJ_CREATE e a espera de um CREATE pendente, como
    o IopParseDevice. O `--start-driver=condrv` carrega o condrv.sys real e
    `ntos/test/console_driver.rs` abre o servidor, a referência e a conexão
    de um console e troca as mensagens CONNECT e DISCONNECT pelos IOCTLs do
    condrv (`CONDRV_OK`);
  - o caminho de console de um programa de console (`ex/console_information.rs`,
    `ps/process_parameters.rs`): o NtSetSystemInformation(132,
    SystemConsoleInformation) que o kernelbase chama quando o
    `\Device\ConDrv\Server` ainda não existe (com o bit DriverLoaded, o
    ZwLoadDriver da chave do condrv sob o ExpConDrvLoadLock e sem checar
    privilégio; sem ele, o SeLoadDriverPrivilege e o ZwUnloadDriver), e os
    ordinais 1 e 2 sem nome que o condrv.sys importa para criar o
    conhost.exe: o PsCaptureUserProcessParameters (o bloco NORMALIZED do
    cliente copiado para um pool 'PsPb' com Buffers absolutos, o diretório
    corrente trocado pelo NtSystemRoot e o console e os handles padrão
    zerados) e o ZwCreateUserProcess (o NtCreateUserProcess com
    PreviousMode KernelMode). O volume do smss leva o conhost.exe, o
    cmd.exe, o net.exe, o net1.exe e o reg.exe com as DLLs deles
    (`CONSOLE_PROGRAMS`) e as fontes do console (Consolas e Lucida
    Console, com a chave `Console`). O NtCreateUserProcess de KernelMode
    (`ps/create_context.rs`) não sonda nada, usa o bloco de parâmetros
    como veio, aceita handles de kernel no ParentProcess e no Token,
    passa o SeSinglePrivilegeCheck e, com OBJ_KERNEL_HANDLE, devolve
    handles de kernel; PROCESS_CREATE_FLAGS_AUXILIARY_PROCESS liga o
    Flags3.AuxiliaryProcess. O NtCreateFile de modo usuário relativo a um
    handle de dispositivo (o `\Reference`, o `\Connect`, o `\Input` e o
    `\Output` do condrv) abre no dispositivo da raiz com
    RelatedFileObject = ela (`ps/user/files.rs`), e o EaBuffer de uma
    abertura de dispositivo, de modo usuário ou do ZwCreateFile, vai
    copiado e validado (IoCheckEaBufferValidity) ao
    AssociatedIrp.SystemBuffer do IRP_MJ_CREATE, com o EaLength na stack
    location (`io_manager::open_related_device_file_with_ea`). O
    ObOpenObjectByPointer de UserMode de um FILE_OBJECT num processo de
    usuário põe o handle na tabela de usuário dele, como um `device`
    sem handle do I/O manager (`ob/open_pointer.rs`: o servidor do
    console que o condrv entrega ao conhost), e a classe 49
    (ProcessConsoleHostProcess) do NtSetInformationProcess grava o
    OwnerProcessId do processo corrente (o ConsoleCommitState do
    kernelbase). O `--console-process` roda no boot comum o cmd.exe real
    com um console sem janela, pelo condrv.sys e pelo conhost.exe reais
    (`ntos/test/console_process.rs`, `CONSOLE_PROCESS_OK`).
- **Os exports que eram os últimos imports de drivers de software** (76,
  cada um no componente dono, conferidos contra o ntoskrnl 19041):
  - SDDL em `se/sddl.rs` (SeConvertSidToStringSid, SeConvertStringSidToSid
    e SeConvertSecurityDescriptorToStringSecurityDescriptor, com as tabelas
    de apelidos de SID, tipos, flags e direitos de ACE do binário e o
    comprimento reservado que o original devolve) e os níveis de assinatura
    em `se/signing_level.rs`, pelos slots nomeados da tabela de callbacks da
    CI (`se/code_integrity.rs`); sem CI inicializada, FALSE/STATUS_UNSUCCESSFUL;
    de modo usuário, o NtGetCachedSigningLevel (a falha da CI, como o
    STATUS_NOT_FOUND de um arquivo sem cache, volta antes de qualquer sonda
    das saídas), o NtCompareSigningLevels (STATUS_INVALID_IMAGE_HASH quando a
    CI diz que o nível não basta) e o NtSetCachedSigningLevel(2) (as checagens
    comuns, a flag 2 recusada, o nível do processo PPL ou o 0 da flag 4, os
    handles e o SE_SET_FILE_CACHE_INFORMATION capturados, a CI com UserMode;
    teste `user_extended_services` com uma SeCiCallbacks de teste quando a CI
    não está carregada);
  - o rastreamento de I/O (`io/io_perf.rs`): com um IoRegisterIoTracking
    ativo, o IofCallDriver carimba a extensão Timestamp do IRP e o
    IofCompleteRequest entrega o tempo decorrido e o DeviceType a cada
    rotina registrada; sem registro os dois ganchos só leem um contador;
  - as rotinas de filtro do FsRtl (`fsrtl/fs_filter.rs`): o
    FsRtlAcquireFileExclusive/FsRtlReleaseFile percorre os callbacks Pre de
    filtro descendo a pilha e os Post subindo, e cai no Fast I/O
    AcquireFileForNtCreateSection ou no ERESOURCE principal do FCB;
  - os links de interface (`io/device_interface.rs`): o link simbólico do
    Object Manager é o nome sem a referência, e quem abre
    `<link>\<referência>` chega ao PDO com a referência no FileName do
    IRP_MJ_CREATE, como no NT; o IoGetDeviceInterfaceAlias monta a irmã de
    outra classe pela instância, pelo GUID e pela referência;
  - as notificações PnP (`io/pnp_notify.rs`): um registro de
    EventCategoryTargetDeviceChange fica ligado ao PDO por trás do
    FILE_OBJECT (IoGetRelatedTargetDevice, PDO retido até o
    IoUnregisterPlugPlayNotification) e só recebe os eventos desse PDO, com
    o FileObject dele na estrutura; um callback em espaço de sessão (o RIT
    do win32k registra mouse, teclado e HID; o win32kfull, o CD-ROM) guarda
    a sessão de quem registrou e o objeto Session dela, e cada entrega fora
    dessa sessão (o work item do System, outra sessão) anexa a um processo
    dela (MmGetSessionById, MmAttachSession) antes de chamar, como o
    PnpNotifyDriverCallback;
  - as notificações de thread (`ps/notify/thread.rs`) têm os três pontos do
    PsSetCreateThreadNotifyRoutineEx: a criação no contexto de quem cria, a
    de rotinas não de sistema no contexto da thread de usuário nova e a saída;
  - o ExRegisterBootDevice (`ex/boot_device.rs`) cria a thread de espera de
    prioridade 31 que, num aviso de remoção, chama o callback do driver até
    60 vezes antes do bugcheck 0x7B;
  - o RtlFreeAnsiString libera pelo ExFreePool (o RtlpFreeStringRoutine), o
    que vale para as strings que a Rtl aloca no pool;
  - a tabela de trampolins (`hal/amd64/win32_thunk.rs`, MAX_WIN32) tem 4096
    stubs, o bastante para os 3070 exports do ntoskrnl 19041.
  O que depende de estado que o OpenNT não tem segue o caminho do NT para
  esse estado: sem hipervisor, o HvlInvokeHypercall devolve 0x1000 e as
  consultas do Hvl STATUS_UNSUCCESSFUL; com firmware BIOS, o
  ExSetFirmwareEnvironmentVariable dá STATUS_NOT_IMPLEMENTED; sem tm.sys, o
  ZwQueryInformationTransaction dá STATUS_NOT_SUPPORTED; sem mup.sys, os
  FsRtlMupGet* também; o MmRemovePhysicalMemory valida e devolve
  STATUS_INSUFFICIENT_RESOURCES, porque o banco de PFN não encolhe.
- **O terceiro lote de exports que eram os últimos imports de drivers**
  (70 exports de função em 42 grupos e o export de dado SePublicDefaultDacl,
  conferidos contra o ntoskrnl 19041; autoteste em
  `test/rtl_strings_sids_exports.rs`, `test/security_session_exports.rs`,
  `test/fsrtl_cc_file_exports.rs` e `test/ke_ex_po_io_exports.rs`):
  - Rtl e CRT: o RtlNextUnicodePrefix anda as árvores da tabela de prefixos
    pelo cursor LastNextEntry (as raízes isoladas têm Parent nos próprios
    links, como o RtlInitializeSplayLinks); RtlAreBitsSetEx, swprintf,
    wcsncpy, os parsers com porta e escopo RtlIpv4/Ipv6StringToAddressExW,
    RtlUnicodeStringToInt64 e RtlValidateUnicodeString; os vetores de
    SID_AND_ATTRIBUTES/LUID_AND_ATTRIBUTES e o RtlSidHashInitialize
    (`rtl/security.rs`, o mesmo hash do access check); os vetores de
    correlação (`rtl/correlation_vector.rs`); o RtlCrc32 (CRC-32C, não o
    IEEE do RtlComputeCrc32); o RtlOpenCurrentUser, que cai no
    `\Registry\User\.Default` sem a chave do usuário, e o
    RtlFormatCurrentUserKeyPath com o usuário do token efetivo;
  - Se: as rotinas de término de sessão de logon (`se/logon_session.rs`):
    a sessão conta referências como no SepReferenceLogonSession (a primeira
    referência de token assume a da criação) e sai do banco com o último
    token; uma sessão marcada pelo SeMarkLogonSessionForTerminationNotificationEx
    chama cada rotina registrada pelo DelayedWorkQueue com (LogonId, Silo,
    Context). SeGetLogonSessionToken, SeQueryServerSiloToken,
    SeSetSecurityAttributesToken[Ex] (as operações ADD/DELETE/REPLACE/
    REPLACE_ALL, compartilhadas com o NtSetInformationToken),
    ZwCompareTokens (`se/token/compare.rs`), SeExamineSacl (as ACEs de
    auditoria simples; as condicionais são puladas), SeGetCachedSigningLevel
    pela tabela da CI e o SePublicDefaultDacl (a ACL de 0x54 bytes do
    SepInitSystemDacls, na `.kdata`). KseRegisterShimEx/KseUnregisterShim
    respondem como o motor de shims não inicializado e PsChargePoolQuota
    levanta a exceção do PsChargeProcessPoolQuota;
  - FsRtl, Cc, Io e Ob: o MCB de 32 bits sobre o MCB grande e o
    FsRtlLookupLastLargeMcbEntry; FsRtlRegisterMupCalls troca a tabela do
    MUP que os FsRtlMupGet* usam; FsRtlNotifyCleanupAll,
    FsRtlRemoveDotsFromPath, FsRtlGetSupportedFeatures (slot 0x10 da tabela
    do Filter Manager) e FsRtlQueryCachedVdl (FSCTL_QUERY_FILE_REGIONS);
    CcIsThereDirtyDataEx e CcSetDirtyPageThreshold; IoSetIrpExtraCreateParameter
    e IoGetFsTrackOffsetState; ZwSetEaFile, ZwNotifyChangeDirectoryFile
    (`io/file/directory_notify.rs`, que também atende o
    NtNotifyChangeDirectoryFile(Ex) de modo usuário: as sondas do
    IO_STATUS_BLOCK e do buffer alinhado a ULONG, o filtro entre 1 e 0xFFF,
    o FILE_LIST_DIRECTORY e o IRP pelo `io/file/irp_service.rs`, ao driver
    do arquivo ou ao file system embutido nos arquivos do volume de boot),
    NtSetInformationFile, NtFsControlFile e
    ZwCreateSymbolicLinkObject;
  - Ke, Ex, Po, Mm e Io: IoSizeOfIrpEx/IoInitializeIrpEx/IoCleanupIrp,
    IoEnqueueIrp, IoSetIoAttributionIrp e IoReportResourceForDetection; os
    releases Exf de push lock, a espera por endereço sobre push lock
    (ExBlockOnAddressPushLock/ExUnblockOnAddressPushLockEx) e o
    ExEnterCriticalRegionAndAcquireSharedWaitForExclusive;
    ExGetSystemFirmwareTable (`ex/firmware_table.rs`, provedores 'RSMB' e
    'FIRM' do kernel e os dos drivers, como o 'ACPI' do acpi.sys, pela classe
    75 do ZwSetSystemInformation); MmAreMdlPagesCached (o CacheAttribute de cada PFN) e
    MmCopyMemory; KeUpdateThreadTag e KeRaiseUserException; os pedidos de
    energia (`po/power_request.rs`, o tipo de objeto PowerRequest com os
    contadores por tipo) e PoNotifyMediaBuffering/
    PoCpuIdledSinceLastCallImprecise (`po/processor_power.rs`).
  Exports e objetos antigos mudaram para o comportamento do 19041: o
  ExQueryWnfStateData recebe (Subscription, ChangeStamp, Buffer,
  BufferSize) e lê pelo NameInstance da inscrição
  (`ex/wnf/subscriptions.rs`); o RtlAppendUnicodeStringToString
  (`rtl/strings_counted.rs`) copia os bytes, aceita o destino exato sem
  lugar para o NUL e recusa com STATUS_BUFFER_TOO_SMALL (o luafv.sys monta
  os caminhos assim); e o \SystemRoot passou a apontar para
  `\Device\BootDevice\Windows`, com o `\Device\BootDevice` ligado ao volume
  de boot, como no CreateSystemRootLink. Com o lote, 400 dos 419 drivers de
  `System32\drivers` desta máquina têm todos os imports do ntoskrnl (eram
  383); o mup.sys, o dfsc.sys, o udfs.sys e o cldflt.sys sobem pelo
  `--start-driver` (teste `drivers-arquivos-rede`). Ficam de fora o mmcss.sys,
  que precisa do host de extensão do MMCSS (id 9, o
  PspInitializeMMCSSCallouts, com a tabela PspGetFreezeState,
  PsGetNextProcessEx, PsGetNextProcessThread e PsQuitNextProcess), o
  appid.sys, que carrega a pilha de rede (fwpkclnt.sys, netio.sys), e o
  luafv.sys, que já passa pelas chaves e pela tradução do \SystemRoot mas
  para no ZwQueryDirectoryFile da raiz do volume com a classe 37
  (FileIdBothDirectoryInformation), que o caminho Zw dos arquivos de volume
  (`io/file/zw.rs`) ainda não atende (STATUS_INVALID_PARAMETER).
- O `xtask` lê fontes do kernel por `#[path]`:
  `ntos/mm/kernel_data_layout.rs` (`.kdata`/`.edata` do PE e páginas de status),
  `ntos/init/export_names.rs` e `ntos/init/native_export_layout.rs` (a EAT do
  PE) e as tabelas das hives de máquina (`ntos/cm/seed.rs`,
  `ntos/cm/session_manager.rs`, `ntos/cm/ini_file_mapping.rs`,
  `ntos/cm/crypto_defaults.rs`, `ntos/cm/current_version.rs` (as pastas
  de programas que o luafv.sys lê), `ntos/cm/setup_state.rs` (o estado de
  setup de uma instalação concluída), `ntos/cm/service/boot_services.rs` e
  `ntos/cm/service/inbox_drivers.rs`, na mesma árvore `cm`/`cm::service`
  de módulos), com que `xtask/src/hive_image.rs` grava os arquivos SYSTEM,
  SOFTWARE, SAM, SECURITY e DEFAULT de `\SystemRoot\System32\config`.
  Esses arquivos de tabela são dados puros: não usam nada do kernel. O
  `kernel/build.rs` inclui `ntos/ke/services.rs` para gerar a ntdll de
  bring-up.
- **Hives do Registro** (`ntos/cm/hive/`, `hive_list.rs`): o namespace
  de `cm/registry.rs` tem um nó no papel do KCB só para as chaves em uso:
  pai, descritor, flags, a célula 'nk' e as referências (os handles, as
  subchaves vivas, a fixação das chaves sem célula e da raiz de cada hive
  montada). O nó de uma chave de hive nasce quando um nome passa por ela
  (CmpCreateKeyControlBlock); sem referências, vai para a lista de
  fechamento adiado (CmpAddToDelayedClose), de onde volta se a chave é
  aberta de novo, e a lista guarda no máximo 2048 nós (o
  CmpDelayedCloseSize): o mais antigo sai da arena. Cada célula tem no
  máximo um nó vivo (o mapa por célula) e o NodeId (geração e posição na
  arena) nunca se repete: um id de um nó que saiu da arena só deixa de
  valer. O conteúdo de uma chave guardada numa hive (nome, valores,
  classe, LastWriteTime, subchaves) é lido das células a cada consulta
  (`registry::KeyView`, sobre `hive/key_cells.rs`): a busca de uma
  subchave é a busca binária no índice (CmpFindSubKeyByName,
  `hive/index.rs::find`) e o NtEnumerateKey anda pelo índice sem criar nó
  (CmpFindSubKeyByNumber): as subchaves da hive em ordem de nome, depois as
  que só existem em memória (as voláteis), também em ordem; o
  KeyFullInformation e o KeyCachedInformation contam pelos máximos que o
  'nk' guarda. Só os nós sem célula (as chaves mestras, as voláteis, as
  subárvores montadas em memória) guardam o próprio conteúdo, e a raiz de
  uma hive tem o nome do ponto de montagem. A carga lê o primário um bin de
  cada vez (`Storage::from_file`, numa janela de 256 KB; só a recuperação
  pelos logs monta a imagem inteira), confere a hive sem copiar nada
  (`tree::check`, que lê cada célula 'sk' uma vez e deixa os descritores
  como o cache da hive) e liga só a raiz (`registry::link_hive`). Cada
  mudança (chave criada ou excluída, valor gravado ou removido, descritor
  trocado) vai direto às células, sob a mesma trava (`hive/key_cells.rs`,
  `hive/index.rs`, `hive/security_cells.rs`), marcando os setores de 512
  bytes sujos; uma operação de célula que falha não muda a chave e marca a
  hive como quebrada (a descarga dela fica recusada). Uma chave excluída,
  ou de uma hive descarregada, sai da arena na hora; com handle aberto,
  fica só o nome e o LastWriteTime até o último handle fechar. O NtFlushKey grava o log incremental (.LOG1/.LOG2
  alternados) e as faixas sujas no primário, entre o bloco base
  invalidado e o validado (`hive/sync.rs`); a carga de um primário
  invalidado aplica os logs (`hive/log.rs`). As chaves voláteis não ganham
  célula. A classe de uma chave (o Class do NtCreateKey, capturado como no
  CmCreateKey: Length ímpar dá STATUS_INVALID_PARAMETER) fica numa
  célula própria da hive (Class e ClassLength do 'nk', com o MaxClassLen
  do pai). O KeyNodeInformation a põe depois do nome, com o ClassOffset
  alinhado a 8, e o KeyFullInformation logo depois do cabeçalho (0x2C),
  como o CmpPopulateKeyNodeInformation e o CmpPopulateKeyFullInformation;
  sem classe, o ClassOffset é 0xFFFFFFFF (`key/information.rs`). O
  WxSaveSysKey do lsasrv grava assim a chave de sistema nas classes de
  `Control\Lsa\{JD,Skew1,GBG,Data}`. A hive SECURITY do build não tem a
  chave `Policy`: o lsasrv instala o banco de política de um sistema novo
  no primeiro boot (o LsapDbInstallPolicyObject).
- **Montagem das hives do boot** (`cm/hive_init.rs`, o CmInitSystem1 e o
  CmpInitializeHiveList): a fase 0 cria as chaves mestras
  (`\REGISTRY\MACHINE`, `\REGISTRY\USER` e `\REGISTRY\A`) e a hive volátil
  HARDWARE (células só na memória, sem arquivo), antes da descrição do
  hardware que `hw_description` grava nela. A fase 1, logo depois de
  montar o NTFS (antes dela, nada escreve em `\Registry\Machine\System`),
  liga a SYSTEM de `\SystemRoot\System32\config\SYSTEM`, cria o
  `CurrentControlSet` como link volátil para o `ControlSet%03d` do
  `Select\Current` (CmpCreateControlSet; a hive guarda `ControlSet001`, que
  as tabelas chamam de `CurrentControlSet`), cria `Hardware
  Profiles\Current` como link volátil para o perfil `%04d` de
  `Control\IDConfigDB\CurrentConfig` (CmpCreateHardwareProfiles; sem o
  valor ou sem o perfil, nada), começa a lista de hives
  (`CurrentControlSet\Control\hivelist`, volátil: o nome do FILE_OBJECT do
  primário de cada hive, vazio para as voláteis, fora as de aplicativo) e
  liga SOFTWARE, SAM, SECURITY e DEFAULT (`\REGISTRY\USER\.DEFAULT`). O
  build grava as cinco hives com as tabelas de `cm/seed.rs`; sem um
  arquivo, as mesmas chaves entram em memória.
- **Links do Registro** (`cm/registry.rs::resolve`): uma chave com
  KEY_SYM_LINK (REG_OPTION_CREATE_LINK, com KEY_CREATE_LINK no pai) no
  caminho troca o prefixo percorrido pelo `SymbolicLinkValue` (REG_LINK) e
  a busca recomeça na raiz, até 64 vezes, como o reparse do CmpDoParseKey;
  o último componente não é seguido com OBJ_OPENLINK. Os handles guardam o
  caminho resolvido (o nome real). Numa chave de link só cabe o
  `SymbolicLinkValue`; CREATE_LINK sobre chave existente é colisão.
  `\REGISTRY\A` só abre relativo a um handle de hive de aplicativo. Classes
  de confiança (CmpOKToFollowLink): as hives do NtLoadKey são não
  confiáveis, cada uma na própria classe ou na do TrustClassKey; depois de
  seguir um link de uma hive não confiável, a chave mais funda alcançada
  precisa estar na mesma hive ou numa hive da mesma classe, senão
  STATUS_ACCESS_DENIED (o `Software\Classes` do NTUSER chega ao
  `<SID>_Classes`, carregado com a raiz do NTUSER como TrustClassKey).
- **Escritor preguiçoso** (`cm/lazy_flush.rs`): a hive de arquivo que fica
  suja arma um KTIMER de 60 s (2 s expedito); a DPC enfileira o
  trabalhador no work item do sistema, que descarrega as hives sujas menos
  as REG_NO_LAZY_FLUSH (`hive_list::lazy_flush_pass`, sem esperar uma
  descarga em curso) e rearma se sobrou sujeira. O escritor fica retido 60
  s depois da montagem das hives (o atraso do boot do CmpCmdInit). O
  desligamento ordenado (`po/shutdown.rs`) chama o `lazy_flush::shutdown`,
  o CmShutdownSystem: para o escritor e descarrega todas as hives, depois
  do ShutdownTime que o ExShutdownSystem(0) grava.
- **Carga e descarga de hives** (`cm/hive_services.rs`, `cm/hive_list.rs`,
  `cm/hive_file.rs`): NtLoadKey/2/Ex/3 vão ao mesmo CmLoadDifferencingKey;
  o NtLoadKey3 captura os CM_EXTENDED_PARAMETER (TrustClassKey, Event e o
  token de acesso ao arquivo, que precisa ser de impersonação: o primário e
  os logs abrem impersonando-o). A carga abre o primário (sem
  compartilhamento, FILE_OPEN_IF quando pode criar a hive; vazio é hive
  nova) e os dois logs, criados ocultos e de sistema se faltarem, antes de
  ler a hive. O NtUnloadKeyEx com handles abertos congela a hive
  (STATUS_PENDING, com ou sem evento) até o último handle; uma hive
  congelada recusa outra descarga com STATUS_TOO_LATE, e as hives do boot
  com STATUS_ACCESS_DENIED. O NtQueryOpenSubKeys(Ex) parte da raiz de uma
  hive e lista os corpos de chave abertos nela e nas chaves abaixo na
  mesma hive (`registry::open_handles_in_hive`, o PID de cada corpo em
  `key/objects.rs`); a contagem do NtQueryOpenSubKeys inclui o corpo da
  própria referência pelo nome, que o Ex pula.
- **Hives de aplicativo e restaurações especiais** (`cm/hive_list.rs`):
  REG_APP_HIVE liga a hive em `\REGISTRY\A\{...}`, devolve o handle da
  raiz, reaproveita a hive de aplicativo já carregada do mesmo arquivo
  (salvo REG_PROCESS_PRIVATE, que não compartilha nem é compartilhada) e a
  descarrega no fechamento do último handle; REG_LOAD_HIVE_OPEN_HANDLE
  devolve o handle da raiz de uma carga comum e o Event da carga é
  sinalizado na descarga;
  REG_WHOLE_HIVE_VOLATILE copia a hive do arquivo para uma hive volátil em
  `<chave mestra>\<raiz>`; REG_REFRESH_HIVE relê o primário de uma hive
  REG_NO_LAZY_FLUSH e reconcilia a árvore (os nós que continuam existindo
  ficam, com os handles).
- **Filtros de registro** (`cm/callbacks.rs`): CmRegisterCallback(Ex) por
  altitude (a legada `425000` aceita repetição), as notificações pré e pós
  das chaves e dos serviços de hive (Flush, Load, UnLoad, Save, Restore),
  os contextos de objeto (CmSetCallbackObjectContext, no ObjectContext de
  cada notificação, devolvidos com RegNtCallbackObjectContextCleanup na
  destruição do corpo ou na remoção do filtro) e a identidade da chave: o
  CM_KEY_BODY leva 'ky02' e, no KeyControlBlock, um bloco de identidade por
  nó (`key/objects.rs`) com o nome em cache do CmCallbackGetKeyObjectID.
- **Serviços do início automático** (mapa em `docs/mapa-cadeia.md`): os
  serviços de modo usuário que o rpcss.dll, o RpcEpMap.dll, o schedsvc.dll e
  o psmsrv.dll pedem e que não tinham provedor. NtCompareObjects (`ob/compare_objects.rs`:
  os dois corpos pelo ObReferenceObjectByHandle sem tipo e sem acesso,
  STATUS_NOT_SAME_OBJECT quando diferem); NtCompareTokens
  (`se/token/compare.rs`: a ordem de comparação do 19041, com o
  SepCompareSidAndAttributeArrays e os atributos de segurança relevantes;
  o rótulo de integridade, guardado fora dos grupos no OpenNT, entra como
  mais um grupo); NtSetUuidSeed (`ex/uuid.rs`: SeAccessCheck em UserMode
  contra a DACL com o SID de serviço do RpcEptMapper, depois o NodeId e o
  ExpUuidCacheValid); NtIsSystemResumeAutomatic (`po/system_state.rs`: o
  PopFullWake, 1 desde o PoInitSystem). O xtask copia desta máquina as
  chaves que esses serviços e o LSM leem (`xtask/src/service_chain.rs`:
  OLE, COM3, Rpc, AllowedCOMCLSIDs, NetworkServiceTriggers, os valores do
  Winlogon sem os do usuário daqui e PriorityControl) e põe no volume os
  ServiceDll dos outros serviços do grupo DcomLaunch. O autoteste é o
  `test/user_service_chain.rs`.
- **Estado de setup** (`cm/setup_state.rs`, só no boot do processo inicial
  real): o convidado é uma instalação concluída. `SYSTEM\Setup` com
  `SetupType` 0 e `CmdLine` vazio (o WinMain do winlogon só roda o setup
  com os dois), `SystemSetupInProgress` e `OOBEInProgress` 0 e
  `SetupSupported` 1, sem `AuditBoot`; na SOFTWARE, `Setup\State`
  `IMAGE_STATE_COMPLETE`, `OOBE\Stats\OOBEUserSignedIn` 1 (o
  IsFirstLogonAfterOOBE do logoncontroller) e os dados persistidos do
  WNF_DEP_OOBE_COMPLETE e do WNF_SHEL_OOBE_USER_LOGON_COMPLETE em
  `Windows NT\CurrentVersion\Notifications\Data` (carimbo 1, ULONG 1), que
  o kernel carrega ao criar a instância do nome. Com eles o OOBEComplete do
  kernel32 dá completo, e o CPolicyMonitor do LSM não espera o fim do OOBE.
  Nenhum nome é publicado pelo kernel: o 19041 só assina o
  WNF_DEP_OOBE_COMPLETE no PnP quando `OOBEInProgress` é 1.
- **Conta de teste** (`xtask/src/test_account.rs`, `--conta-de-teste`, só com
  `--initial-process=smss`): o volume leva em `SYSTEM\Setup` o `SetupType` 2 e
  um `CmdLine`, o gancho de primeiro boot que o winlogon de uma instalação
  concluída roda uma vez, como SYSTEM, antes do LogonUI (o mesmo que o Setup do
  Windows usa). O comando roda o cmd.exe, o net.exe e o reg.exe reais: cria a
  conta local `Usuario` sem senha, põe no grupo Administradores, desabilita o
  Administrador e o Convidado (o banco novo do samsrv os deixa habilitados com a
  política de produto desta máquina) e volta o `SetupType` a 0 e o `CmdLine` a
  vazio. Com uma única conta local habilitada e de senha vazia, o LogonUI entra
  nela sozinho; nenhuma senha fica no Registro. Os nomes do grupo e das contas
  embutidas vêm das mensagens do samsrv.dll.mui do idioma do convidado, e o
  comando tem no máximo 259 caracteres (o buffer do winlogon). O banco novo tem
  a complexidade de senha ligada: a conta fica sem senha porque o `net user
  /add` não grava senha nenhuma.
- **Chaves do AppX que o xtask grava** (`xtask/src/inbox_packages.rs`): só a
  configuração estática que a imagem do 19041 já traz antes de qualquer
  logon, igual em toda instalação; o AppXSvc e o AppReadiness abrem essas
  chaves e não as criam. Nada por máquina, por pacote registrado ou por
  usuário: nenhum banco do StateRepository, registro de pacote,
  identificador de pacote, GUID de volume ou SID; o registro dos pacotes, o
  estado por usuário e os identificadores são feitos pelos serviços no
  convidado. O teste `appx_keys_carry_no_package_state` confere a lista.
  - `Appx`: os valores de configuração da imagem (`APPX_VALUES`: os
    diretórios `PackageRepositoryRoot` e `PackageRoot`, os tipos de sistema
    de arquivos aceitos, as ACEs condicionais e os recursos ligados), sem as
    subchaves de estado (Inventory, PackageState, PackageRepair...).
  - `Appx\PackageVolumes` com o volume padrão `1`: `DefaultVolumeKey` e
    `EnableExternalVolumes` 1, `Flags` 0x17A, `SISPath`
    `C:\Program Files\WindowsApps` e `MediaId`, `MountPoint` e `Name`
    vazios, sem identificador; o `MutablePackagesOnline` vazio. O
    VolumeManager abre a chave em cada implantação.
  - `Appx\DeploymentExtensionModules`: as duas extensões da caixa de
    System32, na ordem em que o AppXSvc as carrega.
  - `Appx\NewDeploymentOperation`, `Appx\ByteCodeQueue` e `Appx\PurgeList`:
    as filas do serviço, vazias numa instalação nova.
  - `AppxAllUserStore\Applications`: a lista dos pacotes provisionados,
    vazia (o convidado não tem pacotes provisionados; os desta máquina não
    vão).
  - `AppxAllUserStore\InboxApplications` e as entradas dos dois pacotes da
    caixa (o `Path` do manifesto em `\Windows\SystemApps`), e
    `AppxAllUserStore\Config\<família>` deles: a lista dos pacotes da caixa
    que a imagem traz e que o AppReadiness registra no primeiro logon.
  - As pastas vazias `\Program Files\WindowsApps` (o `SISPath`) e
    `\ProgramData\Microsoft\Windows\AppRepository\Packages` (onde o AppXSvc
    cria a pasta de metadados de cada pacote que registra), com o descritor
    da instalação (`host_security`); o conteúdo desta máquina não vai.

## 5. Testes

- **Autotestes no QEMU** ficam em `ntos/test/` e rodam conforme
  `--kernel-test-scope`. A suíte completa:
  `cargo xtask test-boot PHASE3_SELFTEST_OK 900000 --kernel-test-scope=all --smp=4 --expect=PHASE4_SELFTEST_OK --expect=PHASE5_SELFTEST_OK --expect=XSTATE_KERNEL_OK --expect=TIME_KEEPING_OK --expect=PHASE6_SELFTEST_OK --expect=MULTIPROCESS_OK --expect=XSTATE_USER_OK --expect=TIME_USER_OK --expect=PIPES_OK --expect=LPC_PORTS_OK --expect=PHASE7_SELFTEST_OK --expect=KBDTEST_OK --expect=SELFTEST_OK`
  (os `--expect` são procurados em ordem, cada um depois do anterior: o
  estado estendido e a hora saem dentro da fase 6, antes do
  `PHASE6_SELFTEST_OK`; o `MULTIPROCESS_OK`, o estado estendido e a hora em
  modo usuário, os pipes e as portas LPC, dentro da fase 7, antes do
  `PHASE7_SELFTEST_OK`). Um sub-teste que deixa de ser chamado some da serial
  e reprova a suíte; por isso os testes `pipes`, `lpc`, `relogio` e `xstate`
  são `coberto_pela_suite`.
- **Validação inteira**: `cargo xtask test-all` (`xtask/src/test_all/`) roda
  a suíte completa com 4 CPUs e com 1 (`suite-smp4`, `suite-smp1`, prazo de
  900 s) e todo `[[teste]]` de `docs/status/components.toml`, cujo `comando`
  é um `cargo xtask test-boot` completo (o test-all troca só o
  `--build-dir`). Cada execução tem a pasta `build/test-all/<id>` (`<id>.<n>`
  com `--repeat`). As opções de boot dos testes (`--kernel-test-scope`,
  `--start-driver`, `--kd`, `--initial-process`, `--storage`, `--display`,
  `--pnp-root`, `--usb`, `--tpm`, `--trace-driver-api`, `--trace-rpc`, `--trace-failures`, `--trace-files`, `--heap-census`, `--perfil`, `--console-mirror`) não entram no
  build: vão no bloco de opções de carga da imagem de boot (abaixo), então
  a rodada inteira compila um kernel só. Uma thread monta as imagens
  (`test-boot --build-only`) uma vez por chave de imagem
  (`BuildOptions::image_key`), em `build/test-all/imagem-<n>`: uma para os
  testes do boot comum e outra para os do smss, cujo volume NTFS leva os
  programas da cadeia e outra hive SYSTEM. Os binários do Windows do bundle
  ficam numa pasta só para todo build (`build/windows`, ou `--windows-dir`);
  a cópia deles preserva a data do original, pula o que já está em dia e
  troca de lugar inteira, para que nem o caminho, nem a cópia, nem um build
  em paralelo recompilem o kernel, e um `cargo xtask build` ou `test-boot`
  com qualquer `--build-dir` reaproveita o kernel que o test-all compilou (e
  vice-versa). `--jobs` pistas rodam o QEMU sobre as imagens prontas, as de
  prazo maior primeiro (`test-boot --no-build --image-dir=<imagens>`): a
  pasta da execução recebe a cópia do `os.img` com as opções de carga dela,
  a saída em `test-boot.log` e a serial em `serial.log`, e o volume NTFS da
  pasta de imagens entra com `snapshot=on` (as escritas do convidado ficam
  num arquivo `vl.XXXXXX` na pasta temporária do QEMU, que o xtask aponta,
  por TMP/TEMP/TMPDIR, para `qemu-tmp` dentro da pasta da execução e apaga
  quando o QEMU termina, também quando o test-all mata um test-boot pelo
  prazo: o QEMU morto não apaga o arquivo), então as pistas o dividem e cada execução
  começa dele intacto, como o `test-boot` sempre faz (o reinício do
  convidado com `--allow-reboot` fica no mesmo QEMU e no mesmo snapshot; o
  `--power-cycles`, que sobe outro QEMU depois do desligamento ACPI, usa uma
  cópia gravável do volume na pasta da execução, apagada no fim); uma execução que passa
  do prazo do test-boot mais o `--hold` e 2 minutos é morta com o QEMU. Um
  QEMU pode comprometer toda a memória do convidado (o QEMU do OpenNT
  compromete a RAM conforme o convidado a toca, §3.5; um QEMU sem o
  `tools/qemu/lazy-ram.patch` compromete tudo ao subir), e com o commit do
  host esgotado processos morrem sem mensagem
  (o próprio test-all, o cargo, o rustc): os QEMUs começam um de cada vez,
  só quando o commit livre (GlobalMemoryStatusEx) cobre a memória do
  convidado, 1 GB do QEMU, uma margem de 6 GB para o build e a memória dos
  QEMUs que subiram há menos de 3 s (que talvez ainda não apareça no
  commit), sem espera fixa entre um QEMU e o próximo. A pasta de uma
  execução que passou é apagada, e a de imagens no fim, quando todas as
  execuções dela passaram (`--keep` guarda tudo); a de uma falha fica, e a
  de imagens dela também, com o `kernel.elf` para simbolizar endereços. No
  fim sai a tabela (teste,
  resultado, build, tempo, log) e, por falha, o motivo dado pelo test-boot, o
  trecho da serial a partir do primeiro marcador de falha (ou as últimas
  linhas, num prazo esgotado) e o comando que repete o QEMU na mesma imagem
  (`--no-build --image-dir=build/test-all/imagem-<n> --accel=<acelerador>`).
  O `test-boot.log` de cada execução diz quando cada saída esperada chegou,
  contado da subida do QEMU (`[xtask] "PHASE4_SELFTEST_OK" aos 12.3 s`).
  Um build ou um QEMU morto de fora (o rustc e os QEMUs fechados à mão
  quando o PC fica lento) roda de novo depois de 30 s, até 40 vezes: o
  build que falhou no cargo sem diagnóstico (`report::build_killed`) e a
  execução cujo QEMU saiu com erro, sem evento SHUTDOWN, antes da saída
  esperada e sem marcador de falha na serial (`report::qemu_killed`; o
  test-boot dá o motivo "QEMU encerrado de fora"). Erros de compilação,
  falhas de teste, prazos esgotados e STOPs nunca se repetem.
- **Acelerador**: o `test-boot` usa `--accel=auto` por padrão: o WHPX (a
  virtualização do processador pelo Windows Hypervisor Platform) quando o
  QEMU o lista no `-accel help` e a partição sobe nesta máquina, senão o
  TCG. A sondagem (`qemu::detect_accelerator`) sobe o QEMU com o WHPX e um
  dispositivo inexistente: o QEMU cria a partição antes dos dispositivos,
  então o erro do dispositivo prova que o WHPX iniciou (uns 100 ms). O
  test-all sonda uma vez e passa o `--accel` a cada execução; `--accel=tcg`
  troca o padrão da rodada, e `acelerador = "tcg"` num `[[teste]]` fixa o
  dele (o `comando` não leva `--accel`). O `run` e o `debug` ficam no TCG,
  que o rastro de instruções do depurador gráfico exige. No WHPX o QEMU
  recebe `-cpu host`, `ignore-unknown-msr=off` (um MSR que o hipervisor não
  conhece dá #GP, como no hardware) e `kernel-irqchip=off`: o LAPIC fica no
  QEMU, como o IOAPIC e o 8259 (`qemu::whpx_machine`). O OpenNT recebe as
  interrupções de dispositivo pelo 8259, e com o LAPIC no hipervisor
  (`kernel-irqchip=on`, o modo x2APIC do WHPX) o QEMU só entrega uma
  interrupção do 8259 numa saída posterior da CPU virtual. Medido com ele:
  o `win32k` levou 66 s até o `WIN32K_LOADED` (19 s com o LAPIC no QEMU, 33 s
  só na criação do arquivo de paginação, E/S de disco). O que o LAPIC no
  hipervisor ganharia são os IPIs: o `suite-smp4` chega ao `KBDTEST_OK` em
  40 s com ele, 59 s sem ele e 62 s no TCG.
  Uma saída para o QEMU no WHPX custa bem mais que uma chamada ao emulador no
  TCG: um byte na COM1 por OUT custava 21 µs (28 µs com o LAPIC no
  hipervisor) contra 3,3 µs no TCG; por isso a serial manda cada lote da
  FIFO num `rep outsb` (7,8 µs por byte; o resto é a escrita de cada byte
  no chardev do QEMU) e o stage2 lê o kernel por DMA.
- **Opções de carga**: como o LoadOptions que o winload monta das opções do
  BCD, o kernel recebe as opções de boot num texto (`DEBUG DEBUGPORT=COM2
  KERNELTESTSCOPE=all STARTDRIVER=NDIS,AFD ...`, `init/load_options.rs`)
  que o xtask grava no último setor da reserva do stage2 (LBA 64), com
  assinatura `LOP1` e tamanho. O setor de boot carrega os 64 setores do
  stage2 em 0x7E00, então o bloco chega em `BOOT_LOAD_OPTIONS_PHYS`
  (0xFC00); o kernel o copia na entrada, antes de qualquer outra CPU e
  antes de o trampolim dos APs reusar aquela memória, e
  `init/boot_config.rs` responde a partir dele (`smss_boot()`,
  `start_driver()`, `kernel_debugger()`...). Sem o bloco, o boot segue sem
  opções. O mesmo `load_options.rs` entra no xtask (`#[path]`), que monta o
  bloco; `test-boot --no-build` regrava só esse setor, então um kernel
  montado serve a qualquer combinação de opções. A ntdll de bring-up está
  sempre no bundle, mas só os boots com autoteste a enxergam
  (`hal/bundle.rs`); `OPENNT_TRACE_SYSCALLS`, um diagnóstico sem opção no
  xtask, continua lido no build.
  `espera_falha = true` no `[[teste]]` tira o teste da rodada padrão (o
  prazo inteiro dele, gasto em toda validação, não prova nada novo): ele
  roda com `--espera-falha`, `--all` ou `--only`, conta a falha à parte, sem
  reprovar a rodada, e avisa quando passa; `coberto_pela_suite = true` tira
  do padrão um teste cujos marcadores as suítes conferem (roda com `--only`
  ou `--all`).
  `na_execucao_de = "<id>"` marca um teste com o mesmo boot de outro (as
  imagens, o kernel, a máquina, o texto das opções de carga e o acelerador,
  com o prazo dentro do do anfitrião e sem entrada pelo monitor, `--hold`,
  depurador, desligamento ou parada esperada; `plan::check_hosts` recusa o
  resto ao carregar). Quando o anfitrião também entra na rodada, o convidado
  não sobe um QEMU: o anfitrião recebe uma `--expect-any` para cada texto do
  convidado que ele mesmo não espera (e o `--watch-screen`, se o convidado o
  tem), e o veredito do convidado sai da serial do anfitrião com a regra do
  test-boot (`report::derived`: a cadeia em ordem, cada texto depois do
  anterior, as `--expect-any` em qualquer ponto, e um marcador de falha antes
  de um texto reprova), com o último texto dentro do prazo do convidado pela
  hora de chegada no `test-boot.log` do anfitrião. A cadeia do boot do smss
  até o LogonUI é uma execução (`logonui`, com onze convidados) em vez de
  doze, e a do `win32k` decide `smss-csrss` e `etw-user`: os marcadores
  dessas cadeias não têm ordem fixa entre si (o `DWM_STARTED` sai antes ou
  depois do `LOGONUI_STARTED`), por isso cada convidado guarda a própria
  cadeia em vez de uma lista ordenada única. Com `--only` só do convidado, ou
  sendo `espera_falha`, ou no `capturas`, ele sobe o próprio QEMU.
  `--cpu-friendly` baixa a prioridade do test-all para BELOW_NORMAL e tira as
  4 CPUs lógicas de número mais baixo da afinidade dele (kernel32, sem
  crate); o cargo, o rustc e o QEMU herdam as duas.
- **Processo de usuário nos autotestes**: um teste que precisa rodar como
  processo de usuário usa `with_test_process`
  (`ntos/test/multiprocess/identity.rs`), que cria um EPROCESS real com
  estado, PEB e uma thread corrente dele e o termina no fim. Identidade
  forjada (PID ou PEB escritos à mão num global) não existe. Os processos e
  threads dos testes multiprocesso pegam ids com `cid::ALLOCATE`, para que
  um objeto vazado por um teste não quebre outro; as asserções sobre um
  processo que já saiu leem o EPROCESS retido pelo teste, não estado global.
  Os buffers que um teste passa aos serviços de um processo de teste são
  memória desse processo (alocados dentro do corpo de `with_test_process`,
  ou anexado a ele): o modo estrito de posse recusa a memória de outro.
- **Drivers reais**: `--start-driver=<serviço>` sobe um driver do volume e
  `--trace-driver-api` mostra cada export chamado (veja o README). O
  Code Integrity sobe no fim da fase 1, antes da árvore de dispositivos,
  como o SepInitializationPhase1 do NT, em todo boot menos o dos autotestes
  (que carregam imagens de kernel sintéticas do sistema de arquivos em
  memória), onde só o `--start-driver` o liga. Sem ele a
  SystemCodeIntegrityPolicyInformation (164) é STATUS_UNSUCCESSFUL, e o
  IsLockdownSKU do KERNELBASE faz falhar o CoInitializeSecurity do combase
  (o primeiro empacotamento COM de um processo). Os drivers que o PnP carrega (o
  acpi.sys, o pci.sys, o msisadrv.sys com o KMDF, o i8042prt.sys e os
  filtros de classe) passam pela validação
  (`CI_KERNEL_IMAGE_RESULT name=\FS\i8042prt.sys status=0x0`). A imagem
  principal de um processo de usuário também passa pela CI, na primeira
  conversão GUI do processo (não na criação da seção, como no 19041): o
  PsConvertToGuiThread pergunta o nível de assinatura
  (`ps/process_image::section_signature_level`, o
  PsQuerySectionSignatureInformation), a CI responde pelo arquivo da imagem
  (`CI_USER_IMAGE_RESULT`) e o nível fica no estado da seção, como no
  Segment+0xF; com nível de pelo menos SE_SIGNING_LEVEL_WINDOWS (12), o
  callout de processo do win32k leva o bit 2, e um processo com a seção
  `.imrsiv` (o explorer.exe) vira "immersive broker" e pode criar janelas
  nas bandas privilegiadas. Uma imagem sem catálogo no volume fica sem o
  bit. Os testes
  `watchdog` e `dxgkrnl` do `components.toml` esperam essa validação e
  depois iniciam o watchdog.sys e o núcleo gráfico (serviço `DXGKrnl`, com
  os valores da chave do Windows) com
  `DRIVER_START_COMPLETED name=<serviço> state=4 win32=0`; o serviço de
  teclado lê do i8042prt.sys e o `--hold=30000` mantém o sistema rodando
  30 s sem falha na serial. Um serviço que o PnP já iniciou (o msisadrv do
  teste `kmdf`) volta ERROR_SERVICE_ALREADY_RUNNING (1056) com state=4. Uma imagem recusada pela CI falha com o status
  real: o NTSTATUS da carga (STATUS_INVALID_IMAGE_HASH) segue até o SCM,
  que mostra o 577 do Windows.
  As chaves
  de serviço dos drivers inbox iniciados assim ficam em
  `cm/service/inbox_drivers.rs`, com os valores da instalação (um driver sem
  ImagePath carrega `\SystemRoot\System32\Drivers\<serviço>.sys`, como no
  IopLoadDriver). Depois do `DRIVER_START_COMPLETED`, com o anel 3 armado,
  `ntos/test/boot_drivers.rs` usa o que o driver publicou: um processo de
  teste lê e grava o `\Device\Null` do null.sys (`NULL_DEVICE_OK`) e manda
  IOCTL_BEEP_SET ao `\Device\Beep` do beep.sys pelo StartIo dele
  (`BEEP_DEVICE_OK`), os reconhecedores do fs_rec.sys respondem a um
  IRP_MN_MOUNT_VOLUME sobre o volume NTFS (`FS_REC_OK`), e dois processos
  de teste cifram e decifram memória pelo `\Device\KsecDD` como o
  cryptbase.dll (`KSECDD_MEMORY_OK`): o ksecdd.sys passa os IOCTLs do
  RtlEncryptMemory à extensão de device control que o cng.sys lhe
  entregou no DriverEntry (0x390048 no `\Device\CNG`), e o CngEncryptMemoryEx
  deriva a chave do boot com o ProcessCookie e a hora de criação do
  processo (SAME_PROCESS, pelo ZwQueryInformationProcess de modo kernel e o
  PsGetProcessCreateTimeQuadPart), com o AuthenticationId do token do
  sujeito (SAME_LOGON; a opção 4 do CredProtectEx usa o do SYSTEM e só a
  sessão 0x3e7 decifra) ou sem nada (CROSS_PROCESS). O ProcessCookie
  (`ps/query_process::process_cookie`) é o mesmo EPROCESS.Cookie nos dois
  modos. Por fim um processo de teste WinTcb-Light faz o cliente protegido
  do LSA e outro faz o lsass.exe (`KSECDD_PROTECTED_CLIENT_OK`): o 0x478 do
  LsapOpenCaller é recusado só com a proteção ligada (o RtlProtectedAccess
  do PspProcessOpen, `ps/open_procedure.rs`), o 0x1000 abre, o CopyVm, o
  AllocVm e o DupLsaHandle do ksecdd servem o cliente (o ZwDuplicateObject
  de modo kernel com handles da tabela de usuário) e o cliente libera a
  faixa pelo 0x390058 do LsaFreeReturnBuffer (o IoGetRequestorProcess
  real).
- **Depurador do kernel, cliente** (`tools/opennt-kd`): só a biblioteca
  padrão. O prompt do `cargo xtask debug` (`xtask/src/debug`) e o
  depurador gráfico usam o mesmo código.
  - Modos do `cargo xtask debug`: sem opções, compila com `--kd=com2`, abre
    o QEMU com a COM2 num socket TCP local e o prompt.
    `--connect=HOST:PORTA` só conecta (a um `cargo xtask run --kd=com2`,
    porta 1234, onde o GDB também entra). `--launch --no-client
    [--headless]` só compila e abre o QEMU para outro cliente: imprime
    `KD_MONITOR 127.0.0.1:PORTA` (com `--monitor-port`, o monitor HMP do
    QEMU) e `KD_READY 127.0.0.1:PORTA`, e fecha o QEMU quando a entrada
    padrão fecha.
  - `--vm-snapshots`, `--record=ARQ`, `--replay=ARQ [--gdb-port=N]`
    (`xtask/src/time_travel.rs`, `xtask/src/qcow2.rs`): os discos entram
    como overlays qcow2 criados pelo próprio xtask (cabeçalho da versão
    3, clusters de 64 KB, refcount e L1 vazios, o disco cru por trás). Com
    `--vm-snapshots` o `savevm`/`loadvm` funcionam e as imagens cruas não
    mudam. A gravação usa `-icount shift=auto,rr=record` com o snapshot
    inicial `inicio`, os discos atrás do `blkreplay`, sempre TCG e a data
    da CMOS fixa no relógio virtual (`ARQ.maquina` guarda data, memória e
    processadores para a reprodução); `OPENNT_RR_SHIFT` troca o passo do
    icount. A reprodução abre o gdbstub do QEMU (`-gdb`, `-S`), imprime
    `KD_REPLAY` e entrega esse endereço em `KD_READY`. Fechar a entrada
    padrão manda `quit` ao monitor antes de matar o QEMU (a gravação só
    vale com a saída normal).
  - Símbolos (`symbols.rs`, `pe.rs`, `pdb.rs`, `msf.rs`): o `kernel.elf`
    com os nomes do Rust legíveis; para cada binário da Microsoft carregado,
    os exports do PE e os símbolos do PDB dele: os públicos, os dados
    globais e, quando o PDB não foi despido, os procedimentos com tamanho e
    as linhas (`sym` e `ln` mostram `arquivo:linha`). O arquivo desta
    máquina só vale quando é a imagem carregada (o mesmo tamanho; na dúvida,
    a data e o checksum do cabeçalho no alvo); sem ele, a identidade do PDB,
    as seções e os exports saem da memória do alvo. Os módulos aparecem sem
    extensão (`ntfs!NtfsCommonCreate+0x1a3`); `nt` é o kernel. Um endereço
    que nenhum símbolo cobre sai como `módulo+0xRVA`; uma parte fria de uma
    função (entrada encadeada da `.pdata`, sem símbolo próprio) sai como a
    função dona mais o deslocamento. `xs [módulo!]padrão` lista os símbolos
    que casam com `*` e `?`.
  - Cache de PDBs (`pdb.rs`): as pastas de `OPENNT_SYMBOLS`, separadas por
    `;` (sem a variável, `build/symbols`); a primeira recebe os downloads.
    Em cada pasta valem `<nome>/<GUID><idade>/<nome>` (a forma do servidor,
    a dos downloads), `<nome>.<GUID><idade>.pdb` e `<nome>`, sempre
    conferidos pelo GUID e pela idade (só o superbloco, o diretório e o
    começo de dois streams são lidos). O que falta vem do servidor público
    (`OPENNT_SYMBOL_SERVER`) pelo `curl`, numa fila de quatro downloads com
    prazo (`OPENNT_SYMBOL_DOWNLOAD=0` desliga); o download é o mesmo do
    `cargo xtask nt-types`. O PDB de um driver entra na fila quando o
    módulo aparece; o de um módulo de usuário, no primeiro uso do módulo
    (os que já estão no cache entram na hora). `módulo!nome` numa expressão
    ou num breakpoint, a linha da parada, `k`, `bt`, `btt`, `ustack`, `sym`,
    `ln`, `?`, `dt módulo!tipo` e `!analyze` passam o PDB que falta para a
    frente da fila e esperam por ele (`OPENNT_SYMBOL_WAIT` segundos, 120
    sem a variável, uma vez por PDB); os que chegam depois entram na parada
    seguinte. `.reload /f` pede todos os que faltam e tenta de novo os que
    falharam; `.reload /w` espera a fila.
  - Pilha (`unwind.rs`, `stack.rs`): o contexto (RIP, RSP e os
    registradores conhecidos) passa de quadro em quadro. Nos binários da
    Microsoft, o desenrolar virtual do x64 como o RtlVirtualUnwind do 19041,
    pela `.pdata` (com as entradas indiretas) e pelo UNWIND_INFO: push,
    alocação, registrador de quadro, registradores salvos por MOV relativos
    ao establisher frame, quadro de máquina e informação encadeada; no
    quadro de cima, só os códigos do prólogo já executados, e o epílogo
    reconhecido pelas instruções (`add rsp`/`lea rsp`, `pop`s, `ret` ou um
    `jmp` de chamada em cauda); função folha. A tabela vem do arquivo desta
    máquina ou da memória do alvo. No código do OpenNT, os frame pointers (e
    o prólogo no quadro de cima). Um driver chamado pelo kernel e o kernel
    chamado pelo driver desenrolam um sobre o outro; os voláteis, e os
    salvos do código sem `.pdata`, ficam desconhecidos no chamador. As
    passagens dos trampolins do OpenNT saem dos símbolos do `kernel.elf`,
    com o `call rel32` conferido no código: a entrada de syscall (o papel do
    KTRAP_FRAME) passa para a pilha do anel 3 pelos registradores que ela
    empilhou e pelo RSP do CONTEXT do intervalo da thread (ou do
    KPCR.UserRsp do processador dela), lida no espaço do processo da
    thread; o trampolim dos exports passa para o código nativo que chamou o
    export pelo CONTEXT que ele salvou; `opennt_kernel_thread_start` e
    `opennt_kernel_thread_return` são o começo da pilha. O `btt` de uma
    thread de usuário sem quadro de troca (uma espera adiada) começa no
    CONTEXT do anel 3 que o `monitor context` dá, no processo dela, e avisa
    quando o RSP está fora da pilha da TEB. `bt`, `k`, `btt` e
    `ustack` marcam cada passagem e terminam com a linha de onde e por que o
    desenrolar parou (`Stop`: fim da pilha, limite, memória ilegível,
    UNWIND_INFO inválido, registrador desconhecido, cadeia de RBP, um
    retorno do kernel para o anel 3 sem passagem); `kernel` no fim deles
    para na entrada de syscall. O `gu` sai pelo quadro de cima do mesmo
    desenrolar.
  - Tipos (`tpi.rs`, `types.rs`): o TPI do `build/symbols/ntkrnlmp.pdb` (o
    mesmo leitor do `cargo xtask nt-types`, que agora o usa daqui) ou, sem
    ele, do PDB com a identidade da seção `[pdb]` do `nt_types.toml` em
    qualquer pasta do cache, baixado na primeira vez que falta.
    `dt _IRP endereço` mostra a struct campo a campo; enums com o nome do
    valor, bitfields, arrays de caracteres como texto, ponteiros com o
    símbolo. `dt módulo!tipo endereço` usa o PDB do módulo. O PDB carrega na
    primeira expressão tipada.
  - Expressões (`expr.rs`): números (`0x`, `` ` ``, `0n`, hexadecimal sem
    prefixo), registradores (`@rax`, `%rax`, `rax`, `@gs_base`),
    `$variáveis` (ou `@$nome`), símbolos do Rust, `módulo!símbolo` e
    `módulo+RVA` (`Windows.UI.Logon+0x48b50`), `poi`/`by`/`wo`/`dwo`/`qwo`,
    `[x]`, `$iment(módulo)`, `sizeof(tipo)`, os operadores do C e os acessos
    tipados (`((_IRP*)@rcx)->Tail.Overlay.CurrentStackLocation`, `*p`,
    `&s.Campo`, `p[2]`).
  - Breakpoints (`client.rs`): software, hardware de execução, escrita e
    acesso (`ba e1|w4|r8`), condição (`bp x 3 /w "@rax == 7"`: a partir do
    terceiro acerto, só com a condição verdadeira; os outros acertos seguem
    sozinhos), adiados (`bu`: o símbolo de um módulo que ainda vai carregar;
    um `bp` num módulo que não carregou vira o mesmo adiado, e um símbolo
    que falta num módulo carregado continua sendo erro) e parada por carga
    de módulo (`sxe ld:ntfs.sys`). Os dois últimos usam
    o filtro de carga do alvo com os nomes dos módulos pedidos (num kernel
    sem o filtro, um breakpoint interno na notificação de carga de imagem,
    `ps::notify::image::notify`, que parava em toda carga, e o ponto de
    evento de imagem `opennt_kd_image_event`): só a carga pedida para a
    máquina, com os argumentos do evento de imagem nos registradores da
    resposta. O cliente traz os módulos (os de usuário do processo da
    carga, quando é uma DLL) e segue sozinho quando nada pede a parada. Um
    adiado (`breakpoints.rs`) resolve o nome só no módulo novo (exports, PDB
    baixado na hora com a máquina parada, ou `módulo+0xRVA`) e arma o
    breakpoint no processo que carregou a imagem. A lista de módulos só é
    relida (`monitor lm`) quando a impressão digital da resposta de parada
    muda, e os registradores da parada vêm da própria resposta.
    `/p <pid|eprocess>`
    prende o breakpoint a um processo; `/p nome.exe` e `/p *` fazem um
    modelo, e cada processo com o nome (também os que nascem depois) ganha
    uma instância. Num endereço de sistema, o `/p` filtra no acerto. Na
    saída do processo (`opennt_kd_process_event`), as instâncias dele somem
    e um `bu` sem `/p` volta a adiado até o próximo processo com o mesmo
    nome. `/max n` desliga o breakpoint depois de n acertos que pararam ou
    registraram; `.bplog on` manda as linhas de log também à saída padrão.
    `.bpsave`/`.bpload` gravam e recriam a lista (com o `/p` por nome e o
    `/max`).
  - Processos de usuário (`user.rs`, `client.rs`): `.process` escolhe o
    processo e o cliente o reaplica a cada parada; numa parada do anel 3, o
    processo dela vira o das leituras. Os módulos de usuário (a PEB.Ldr e as
    imagens do VAD) entram nos símbolos à parte (`set_user_modules`), com os
    exports do PE desta máquina e o PDB público. Os de outro processo ficam
    guardados pela base e pelo caminho para a volta. Um `módulo!nome` de uma
    DLL que ainda não está na lista relê a PEB.Ldr e o VAD do processo
    escolhido (uma vez por parada), então o `bu` numa DLL do processo
    escolhido que ainda vai carregar arma na parada de carga dela. A pilha
    de uma thread de usuário sai do CONTEXT salvo dela. Comandos: `.process`, `lmu`,
    `handles`, `vad`, `uthreads`, `ustack`, `kmap`, `events`, `uex`;
    `handles`, `vad` e `uthreads` sem processo valem o do `.process`, o TID
    do `ustack` pode ser expressão (`$t_tid`, ou `{$t_tid}` como no campo do
    `print`) e `thread` sem número mostra a thread do protocolo e o que roda
    no processador dela.
  - Eventos e breakpoints com ação: `sxe cpr[:nome]`, `epr`, `ct[:pid]`,
    `et` e `ld:processo!dll` (breakpoints internos nos pontos de evento do
    kernel, filtrados pelo cliente); `bp x /log "texto {expr}"` registra e
    segue; `/cmd "r; k"` roda comandos na parada; `/g grupo` com `bgd` e
    `bge`; `bar w|a <início> <tamanho>` divide a faixa em até quatro
    comparadores.
  - Análise (`analysis/`): um decodificador x86-64 próprio (tamanho,
    desvios, operandos relativos ao RIP e imediatos; conferido contra o
    iced-x86 em 8 milhões de instruções dos binários da máquina), o grafo de
    fluxo de uma função com layout em camadas, as buscas de referências a
    strings ASCII e UTF-16, constantes, chamadas entre módulos e xrefs, os
    padrões com curingas, as strings soltas, a linguagem de roteiros e as
    notas (comentários, rótulos, marcadores) e patches por módulo + RVA.
    Também:
    - `functions`: limites de função pela `.pdata`, pelo tamanho do símbolo
      ou por uma passada no fluxo de código (os blocos contíguos a partir da
      entrada, sem seguir `call`); laços pelos desvios para trás dentro da
      função; as marcas dos colchetes da desmontagem;
    - `args`: as escritas simples que preparam RCX, RDX, R8, R9 e
      `[rsp+0x20...]` antes de um `call` (`mov r, imm`, `lea r, [rip+x]`,
      `xor r, r`, `mov r, r2`, `mov r, [rip+x]`, `mov [rsp+x], r/imm`) e o
      valor de cada argumento;
    - `prototypes`: os protótipos das APIs comuns do kernel, da ntdll e do
      Win32 e o comentário da chamada (texto apontado, UNICODE_STRING,
      OBJECT_ATTRIBUTES, tag de pool, símbolo; os deslocamentos das
      estruturas saem do PDB do ntoskrnl quando os tipos estão carregados);
    - `refs::xref_index`: o índice de referências cruzadas de um módulo.
  - Imagens e o `--launch` (`image.rs`, `launcher.rs`): a imagem de um
    módulo para as análises e o `cargo xtask debug --launch --no-client`,
    usados pelo `opennt-re` e pelo `opennt-mcp`.
  - Registradores além dos gerais (`registers.rs`,
    `Client::extended_registers`): x87, MMX, XMM, MXCSR (do `g`), a metade
    alta dos YMM e DR0-DR7 (as extensões do alvo por `p`).
  - Opções de breakpoint (`BreakpointOptions`, `Client::edit_breakpoint`):
    nome, condição de log, condição de comando, uma vez só, silencioso e
    retorno rápido; voltam pelo arquivo de sessão. Breakpoints de memória
    por página (`bpm <a|w|x> <expr> [bytes]`, `bpmc`), pelo `monitor membp`
    do alvo, com o processo escolhido.
  - Bugcheck (`bugcheck.rs`): `!analyze` dá o nome do código, o sentido de
    cada parâmetro (os códigos comuns da referência pública), o driver
    culpado (o módulo da instrução que falhou, o primeiro quadro fora do
    kernel, o KiBugCheckDriver do alvo ou o módulo de um parâmetro) e a
    pilha.
  - Rastro (`trace.rs`, `commands.rs`): `trace [n] [ate <expr>] [ret]
    [over] [entra|sai <módulo>] [pula <módulo>] [vigia <expr> [bytes]]` arma
    o rastro no alvo e lê os lotes até o fim. O cliente guarda o estado dos
    registradores com pontos de controle a cada 256 registros e monta a
    árvore de chamadas pela profundidade. `trace show`, `trace tree`, `trace
    save` (CSV), `trace ref` e `trace diff <arq.csv>` (a primeira
    divergência entre dois rastros, alinhados pelo primeiro RIP comum).
  - Comandos do WinDbg: `k`, `r`, `db`/`dw`/`dd`/`dq`/`da`/`du`, `bp`,
    `bu`, `ba`, `bl`, `bc`, `bd`/`be`, `g`, `p`, `t`, `gu`, `lm`, `lmv`, `?`,
    `ln`, `dt`, `sxe`/`sxd`, `.reload`, `!process`, `!thread`, `!irp`,
    `!devobj`, `!drvobj`, `!object`, `!handle`, `!analyze`, além dos do
    OpenNT (`ps`, `threads`, `cpus`, `obj`, `log`, `btt`, `context`...).
  - Fluxo, monitor de APIs e IRPs (`stream.rs`, `api_monitor.rs`,
    `irp_timeline.rs`, `ntstatus.rs`, `monitoring.rs`): a conexão separa
    os `O` do fluxo do texto (`Connection::take_records`); o `Collector`
    descarta repetidos e conta falhas de sequência. `api_monitor_start`
    lê os nomes (`api names`), manda as especificações dos protótipos de
    `analysis::prototypes` e liga o monitor e a entrega. Cada chamada vira
    uma `ApiRow` (argumentos com nome, resultado com o NTSTATUS pelo tipo
    do resultado, módulo e símbolo do chamador); filtros e CSV. A vida dos
    IRPs (`Timeline`): começa na criação ou no primeiro IofCallDriver, os
    saltos com profundidade e a volta casada pela pilha de chamadas
    abertas, a conclusão, as rotinas (STATUS_MORE_PROCESSING_REQUIRED
    devolve o IRP à vida) e o fim no IoFreeIrp ou na conclusão; o mesmo
    endereço depois do fim é outro IRP. `fetch_records` lê o resto com a
    máquina parada.
  - Exploradores (`explore.rs`): as páginas de `reg`, `objdir` e `fs` em
    estruturas, os tipos REG_* e o texto de um valor, datas do NT.
  - Vista como tipo (`struct_view.rs`): a árvore plana de um tipo num
    endereço (chaves pelo caminho dos nomes), com structs, arrays (até
    256), ponteiros seguidos e listas (LIST_ENTRY pelo Flink, até 256
    entradas, cada uma como a struct que a contém: as listas conhecidas do
    NT ou a mesma struct pelo mesmo campo, ou `Tipo.Campo` escolhido), e a
    edição de um escalar (inteiros com e sem sinal, ponteiros, enums pelo
    nome, bitfields lidos e regravados, floats). `Client::types_for` usa o
    PDB do ntoskrnl ou o de um módulo (`ntdll!_PEB`).
  - Snapshots e reprodução (`hmp.rs`, `monitoring.rs`): o monitor HMP do
    QEMU (`savevm`, `loadvm`, `delvm`, `info snapshots`, `info replay`).
    Depois do `loadvm`, a parada é relida e os breakpoints de software da
    sessão são regravados. `set_replay` passa a sessão para o gdbstub do
    QEMU: `monitor` é recusado sem ir ao alvo (o `qRcmd` dele iria ao
    HMP), os módulos vêm de `ARQ.modulos`, e `reverse_step`/
    `reverse_continue` mandam `bs`/`bc` quando o `qSupported` diz
    `ReverseStep+`.
  - Comandos de texto: `apimon`, `irptrace`, `reg`, `regv`, `objdir`,
    `fsls`, `fscat`, `dtv`, `snap` e `rstep`/`rcont`.
  - Roteiros do kd (`kd_script.rs`): a linguagem do `cargo xtask test-boot
    --kd=com2 --script=ARQ`, do `cargo xtask debug --script=ARQ` e da aba
    Script e do `--script` do `opennt-re` (o `ScriptOptions::capture` leva
    a saída para a janela no lugar da saída padrão), dos roteiros do
    `opennt-dbg` e da ferramenta `kd_script` do `opennt-mcp`. Esses dois
    rodam pelo `run_script_hosted` com um `ScriptHost`: o anfitrião recebe
    as linhas, pode cancelar, dar um prazo (as esperas não passam dele e
    nenhum comando começa depois), passar o log da COM1, atender uma
    parada antes dos tratadores e responder a um comando no lugar do
    depurador; o `ScriptOutcome` diz a linha que falhou, os comandos e as
    variáveis. `check_script` confere a sintaxe sem rodar. A ferramenta
    `run_script` do `opennt-mcp` ainda usa a linguagem antiga de
    `analysis/script.rs`.
    Uma linha por comando; `#` no começo da linha
    comenta. Uma linha que não é da linguagem vai ao depurador como no
    prompt (`bp`, `continue`, `k`...), e a saída dela fica guardada para as
    conferências e os `save-*`. O roteiro inteiro é lido antes de rodar: um
    bloco sem `}` ou um `leave` fora de laço é erro com a linha, sem nada
    rodar.
    - Saída: cada comando sai como `[kd-script] > comando` e a saída dele
      como `[kd-script]   linha`. As linhas dos breakpoints de log, a linha
      de acerto e a saída dos comandos de acerto saem como `[kd-log] ...`
      quando chegam, e não só no fim. Tudo vai à saída padrão (o log do
      test-boot) e à transcrição `kd-sessao.log`, ao lado do `serial.log`
      (no `--connect`, em `<build>/kd-sessao.log`); a transcrição termina
      com o erro, se houver. O DbgPrint já está na COM1 e não se repete.
    - Esperas: `wait-stop [ms]` (padrão 120000), `wait-serial [/t ms]
      <texto>` (padrão 300000; o texto em qualquer ponto da COM1) e `sleep
      <ms>` (padrão 1000) leem a conexão enquanto esperam. O prazo é um
      número, `$variável` ou expressão (`sleep $espera`, `sleep 2*0n60000`);
      um prazo que não dá número é erro. Se o alvo fecha a conexão durante
      uma espera (o QEMU terminou ou foi fechado), o erro traz o fim da
      COM1. Um breakpoint de log, uma
      condição falsa e a carga de um módulo seguem sozinhos, e um tratador
      roda. Uma parada sem tratador encerra o `wait-stop`. No `wait-serial`
      ela é erro, porque a COM1 não anda com a máquina parada (com a máquina
      já parada, o erro sai depois de 2 s). No `sleep` a máquina fica parada
      até o fim do tempo. Os comandos `/cmd` de um breakpoint que para rodam
      quando a parada chega numa espera. Depois de `detach` as esperas só
      olham a COM1.
    - Conferências: `expect <texto>` e `expect-not <texto>` (a saída do
      comando anterior tem ou não tem o texto), `expect-stop <texto>` (a
      última parada), `expect-console <texto>` (o DbgPrint e as linhas de
      log recebidos) e `expect-eq <expr> <expr>`. A falha diz o arquivo, a
      linha e o texto dela (com o `${...}` já trocado). As que olham a
      saída mostram o comando anterior, a linha dele e a saída, até 100
      linhas. O `expect-console` mostra as últimas 60 linhas do console e o
      `wait-serial` as últimas 20 da COM1. Dentro de laços e tratadores, a
      falha diz onde a execução estava (`dentro de: for-each da linha 30
      ($t = 0x...) > on-break ...`).
    - Variáveis: `save <nome> <expr>` (número) e `set <nome> <texto>`. Da
      saída do comando anterior: `save-word <nome> <texto> <coluna>
      [ocorrência]` (o número na coluna da linha que tem o texto; colunas a
      partir de 0, negativas contam do fim), `save-text` (o mesmo, a palavra
      como texto), `save-after <nome> <rótulo> [ocorrência]` (a palavra
      depois do rótulo, na mesma linha), `save-line <nome> <texto>
      [ocorrência]` (a linha inteira), `save-count <nome> <texto>` (quantas
      linhas têm o texto) e `save-thread <nome> <texto> <coluna> <módulo>`
      (a primeira thread dessas linhas com um quadro do módulo na pilha).
      Sem nenhuma linha com o texto exato, `save-word`, `save-text`,
      `save-line` e `save-thread` aceitam o texto sem diferença de
      maiúsculas (o `lmu` mostra `msv1_0.DLL`). Um
      texto com espaços vai entre aspas. `$nome` vale nas expressões quando
      o valor é número; `${nome}` é trocado pelo texto em qualquer linha
      antes de ela rodar, e `${nome.N}` pela palavra N do texto. O `{expr}`
      do `/log` e do `print` continua sendo avaliado na hora.
    - Condições: `if <condição> {`, `} else if <condição> {`, `} else {` e
      `}`. A condição é uma expressão do depurador (diferente de zero é
      verdadeiro), uma comparação de textos (`"${p_name}" == "smss.exe"`,
      `!=`, `contains`) ou uma destas: `output-has <texto>`, `console-has
      <texto>`, `serial-has <texto>`, `stop-has <texto>`, `stack-has
      <ethread> <módulo>`, `defined <nome>`, `running`, `stopped`,
      `wait-serial [/t ms] <texto>` (espera; verdadeira se o texto chegou no
      prazo) e `wait-stop [ms]` (verdadeira se a máquina parou no prazo).
      `not` na frente inverte.
    - Laços: `while <condição> {`, `repeat <n> [variável] {` (a variável vai
      de 0 a n-1) e `for-each <coleção> <v> [filtro valor]... {`. Coleções:
      `thread` (filtros `pid`, `state`, `process` e `stack <módulo>`; `$v` é
      o ETHREAD, com `$v_tid`, `$v_pid`, `$v_start`, `${v_state}` e
      `${v_process}`), `process` (filtro `name`; `$v` é o EPROCESS, com
      `$v_pid`, `$v_cr3`, `$v_threads` e `${v_name}`), `module` (os módulos
      do kernel; filtro `name`; `$v` é a base, com `$v_end`, `$v_size`,
      `${v_name}` e `${v_path}`), `umodule` (os módulos de usuário do
      processo escolhido com `.process`; também `$v_entry`), `cpu` (`$v` é o
      número, com `$v_irql`, `$v_pcr`, `$v_thread`, `$v_rip`, `$v_owner` e
      `${v_process}`) e `line` (as linhas da saída do comando anterior;
      filtro `containing`; `${v}` é a linha e `$v_index` o número dela). O
      `name` e o `process` aceitam o nome sem a extensão (`smss`, `ACPI`).
      `leave` sai do laço e `next` passa à próxima volta (`break` e
      `continue` continuam sendo os comandos do depurador). A lista é lida
      uma vez, no começo, com a máquina parada; o `stack` é conferido em
      cada volta. Depois do laço as variáveis ficam com o último item e
      `$v_count` diz quantas voltas rodaram: `for-each thread t state
      Waiting stack ACPI { leave }` acha uma thread. `while` e `repeat`
      param com erro em um milhão de voltas.
    - Tratadores de parada: `on-break <breakpoint> { ... }` registra os
      comandos que rodam quando o breakpoint para a máquina durante uma
      espera. O breakpoint é `#n`, `*` (qualquer breakpoint) ou a expressão
      com que ele foi criado (ou outra que dê o mesmo endereço). Dentro do
      tratador, `$bp` é o número do breakpoint e `$hits` o acerto. Quando o
      tratador termina, a máquina segue e a espera continua; `stop` deixa a
      máquina parada e encerra a espera. Uma parada dentro de um tratador
      não chama outro. `on-break <breakpoint> off` tira o tratador;
      registrar o mesmo alvo de novo troca o anterior.
    - Outros: `echo <texto>`, `print <texto com {expr}>` (o formato do
      `/log`), `exit` (termina sem erro) e `fail <texto>` (termina com
      erro).
  - Testes (`cargo test -p opennt-kd`): pacotes, resposta de parada,
    registradores, PE e `.pdata`, UNWIND_INFO e o desenrolar misto sobre uma
    pilha montada, públicos de PDB, tipos sobre um TPI montado, expressões,
    bugcheck, o formato do rastro, a árvore de chamadas e a comparação. Contra
    um alvo de mentira num socket local (`tests/fake_target.rs`, o stub em
    `tests/support/fake_stub.rs`, também usado pelos testes do `opennt-mcp`): a
    sessão inteira com breakpoints, passo por cima numa recursão,
    breakpoint condicional com contagem, a parada por carga de módulo, os
    registradores estendidos, as opções de breakpoint (condição de log, uma
    vez só, silencioso, o arquivo de sessão) e o breakpoint de memória por
    página. Também os limites de função, os laços, os argumentos, os
    protótipos e o índice de referências cruzadas. E os registros do
    fluxo, as linhas do monitor de APIs (especificações, decodificação,
    filtros, CSV), a vida dos IRPs (CREATE por dois drivers, conclusão,
    MORE_PROCESSING e IoFreeIrp), os exploradores, a árvore de tipos com
    lista e edição, a tabela do `info snapshots` e, contra o alvo de
    mentira, a reprodução: um passo e o passo para trás de volta ao RIP de
    antes. Os roteiros: a leitura dos blocos e os erros de sintaxe, as
    variáveis `${...}`, as colunas e a comparação de textos e, contra o alvo
    de mentira, as linhas de log na transcrição antes da parada, o tratador
    que deixa a máquina parada e o que a faz seguir até o terceiro acerto,
    os laços pelas linhas, processos e threads, a espera pela COM1 com prazo
    e as mensagens de erro com o comando anterior, a saída e a volta do
    laço; o `sleep` com `$variável` e o erro de um prazo que não é número;
    o `bp` num módulo ausente que fica adiado; e o roteiro com anfitrião (as
    linhas, o `attach` e o `detach` dele, a COM1 por arquivo que cresce, o
    Cancelar, o prazo, a parada atendida, a linha que falhou e as
    variáveis).
- **Depurador gráfico** (`tools/opennt-dbg`, binário `opennt-dbg`).
  - Uso: `cargo run -p opennt-dbg --release -- --launch` roda o mesmo build e
    QEMU do `cargo xtask debug --launch` e abre a janela (as outras
    `--opções` vão ao `xtask`: `--initial-process=smss --display=basic`);
    `--connect=HOST:PORTA` entra num QEMU aberto e aceita só a porta ou a
    linha `KD_READY 127.0.0.1:PORTA` colada; `--serial-log=ARQ` diz o log
    da COM1 desse QEMU (padrão `<build>/serial.log`); `--session=ARQ` abre
    uma sessão salva; `--script=ARQ` roda um roteiro do kd depois do
    attach.
  - Abrir ou conectar (Ctrl+O): o campo das opções do `xtask`, botões das
    opções comuns, as últimas opções usadas, o diretório de build e o QEMU
    sem janela; ou o endereço de um QEMU já aberto (os últimos ficam em
    `estado.json`). Cancelar durante o build, a subida do QEMU ou a conexão
    mata o `cargo` (e com ele o `xtask`, o `rustc` e o QEMU).
  - Sessões com nome (Ctrl+S): os breakpoints no texto do `.bpsave`, as
    expressões observadas, a memória e as opções de abertura em
    `<build>/opennt-dbg/sessoes/<nome>.json`. Abrir troca os breakpoints
    (na hora com a máquina parada, senão na próxima parada ou no attach).
  - Roteiros (Ctrl+R): o executor do `opennt-kd` (`run_script_hosted`, a
    linguagem inteira do `--script` do `cargo xtask test-boot --kd=com2`),
    com a janela como anfitriã (`WindowScript` em `backend.rs`). O roteiro
    é conferido inteiro antes de rodar; cada comando vai ao painel Comandos
    na hora, a barra de estado mostra a linha, o Cancelar para entre
    comandos e nas esperas, e a primeira conferência que falha para o
    roteiro. Na janela, `attach` não faz nada e o `wait-serial` lê o log da
    COM1 da sessão. As variáveis numéricas valem nos comandos digitados
    depois. A
    gravação (Ctrl+Shift+G) escreve os comandos digitados, os botões de
    execução (com `wait-stop` depois de um `c`) e os breakpoints da margem
    e do painel num roteiro que o `cargo xtask debug --script=ARQ` roda.
  - Falhas: a conexão que cai, o QEMU que termina (a linha `KD_QEMU_EXITED`
    do `xtask`), a abertura ou o attach que falha aparecem num aviso no
    alto da janela com como o QEMU saiu, um `*** STOP` ou pânico na COM1,
    as últimas linhas da COM1 e do `xtask`, e os botões Reiniciar ou
    Conectar de novo.
  - Interface: egui/eframe (Rust puro, backend OpenGL `glow`, sem wgpu) com
    painéis encaixáveis do `egui_dock`. Arranjo padrão: Desmontagem e
    Código-fonte no centro; Registradores, Observação e Variáveis locais à
    direita; Pilha de chamadas, Breakpoints, Módulos, Threads, Processos e
    CPUs e Objetos do NT embaixo à direita; Comandos, Rastro e Memória
    embaixo; DbgPrint e o log da COM1 no canto. O arranjo, o tema, as
    expressões observadas e o histórico de comandos ficam em
    `%APPDATA%\opennt-dbg\estado.json`. O menu Painéis reabre um painel
    fechado e restaura o arranjo padrão. Os breakpoints da sessão ficam em
    `<build>/opennt-dbg/breakpoints.txt` e voltam no próximo attach
    (adiados quando o módulo ainda não carregou).
  - Barra de ferramentas com ícones desenhados e dicas; teclas do WinDbg:
    F5 continua, F10 passa por cima, F11 entra, Shift+F11 sai, F9 liga ou
    tira o breakpoint na linha escolhida, Ctrl+B para, Ctrl+Shift+F5
    reinicia, Shift+F5 desconecta, Alt+1 a Alt+9 abrem os painéis e F1
    lista os atalhos. Os botões de execução só valem com o backend livre
    (segurar o F10 não empilha passos). O painel Comandos tem rolagem
    virtual. Barra de estado: conexão, estado do alvo, CPU, thread,
    processo, IRQL, o roteiro rodando e a gravação. Tema escuro e claro.
  - Painéis: Desmontagem (iced-x86, sintaxe MASM, marcador do RIP, margem
    de breakpoints, destinos dos desvios; botão direito: breakpoint,
    executar até aqui, memória); Código-fonte (a linha do DWARF);
    Registradores (os que mudaram em vermelho, editáveis, com o símbolo do
    valor; seletores decodificados com a base de FS e GS; DR0-DR7 com o DR6
    e o DR7 em palavras; XMM e YMM em hexadecimal ou por lanes inteiras e
    de ponto flutuante; x87, MMX e MXCSR); Observação
    (expressões com valor e tipo; um valor tipado abre a struct campo a
    campo, e campos de struct e ponteiros abrem de novo); Variáveis locais
    (parâmetros e variáveis do quadro de cima pelo DWARF do `kernel.elf`:
    frame base, registradores e listas de posições, pelo `gimli`; o
    `cargo xtask debug`, que o depurador roda, compila o perfil `depuracao`,
    com o DWARF completo; os builds comuns levam só as tabelas de linha, que
    bastam para o arquivo:linha e os nomes de função, mas não para as
    variáveis); Memória
    (bytes, words, dwords, qwords, ponteiros com símbolo, ASCII, UTF-16;
    procura de bytes, texto ou UTF-16; um qword que parece ponteiro segue
    com um clique e "voltar" desfaz; a janela também como uma struct do PDB
    do ntoskrnl, campo a campo); Pilha de chamadas (RSP, módulo, função e
    arquivo:linha de cada quadro e o método do desenrolar; numa thread de
    um processo de usuário parada no kernel, segue pelo CONTEXT de usuário
    salvo da thread, com os módulos do processo, que vira o processo das
    leituras); Breakpoints (condição, contagem, acertos, adiados, carga de
    módulo, eventos, por página; log, comandos, grupo e as opções de acerto
    num editor; ligar e desligar um grupo); Módulos (do sistema e do
    processo das leituras, escolhido na lista; o estado do PDB: o ELF do
    OpenNT, PDB público, baixando, falhou, só exports ou sem arquivo, com o
    nome e a identidade do PDB; clique abre o `lmv`); Processos e CPUs (o
    `.process` pelo botão direito) e Threads (estado, motivo e modo da
    espera, prioridade e base, suspensão e tempos, lidos do KTHREAD pelos
    offsets e enums do PDB do ntoskrnl); Objetos do NT (as consultas do `kd/inspect.rs`,
    o módulo e qualquer struct do PDB; endereços azuis abrem como IRP,
    dispositivo, driver, thread ou processo pelo botão direito); Análise do
    bugcheck (abre sozinha numa parada pelo KeBugCheckEx); Rastro; Comandos
    (histórico e Tab para completar comandos, símbolos e tipos); DbgPrint e
    o log da COM1 (filtro, cada parada marcada na linha em que aconteceu e
    a lista delas; `--serial-log=ARQ` ou o campo do painel acompanham o
    `serial.log` de um `xtask` aberto à parte, e o `--connect` usa o do
    diretório de build). As leituras caras (o resto do estado do
    processador, o KTHREAD de cada thread e a parte de usuário da pilha) só
    entram com o painel que as mostra aberto e a opção dele ligada.
  - Rastro: os modos do `trace` (N instruções, até um endereço, até o
    retorno, até entrar ou sair de um módulo), "só a função corrente",
    módulos pulados e um endereço vigiado. A tabela é virtual (centenas de
    milhares de linhas), com filtro por módulo, símbolo ou instrução.
    Escolher uma linha mostra os registradores naquele ponto (os que
    mudaram em vermelho) e os operandos de memória da instrução, com o
    endereço calculado pelos registradores e o valor lido (o registrador de
    destino no passo seguinte) ou gravado. Também: a árvore de chamadas,
    "na desmontagem", exportar CSV, usar como referência ou carregar uma
    referência, e a comparação que vai à primeira divergência.
  - Rastro rápido (QEMU, TCG): liga o log de execução do QEMU (`log
    exec,nochain` pelo monitor HMP) enquanto a máquina roda, até um
    endereço ou por um tempo, e expande cada bloco executado nas instruções
    dele (até o primeiro desvio ou o começo do bloco seguinte). Só RIPs, sem
    registradores. O QEMU 11.1 desta máquina tem o suporte a plugins TCG
    (`-plugin` existe), mas a instalação não traz os plugins de exemplo
    (`libexeclog.dll`): por isso o caminho é o log do `-d`.
  - O backend (`backend.rs`) fala com o alvo numa thread e publica um
    snapshot por parada; a janela nunca espera o socket. `scenario.rs` tem
    os roteiros sem janela do teste e das capturas.
  - Teste de fumaça (`cargo test -p opennt-dbg --release -- --ignored`,
    `tests/smoke.rs`), sem janela: abre o OpenNT com o QEMU sem tela, anexa
    no começo do boot, para na carga do ACPI.sys real (`sxe ld`), para
    dentro dele no retorno de uma chamada ao IoCreateDevice e confere a
    pilha pela `.pdata` com os nomes do PDB público, confere as vistas (o
    módulo e a linha de cada quadro, o estado do PDB, o SSE e o DR7, o
    KTHREAD de cada thread), rastreia 200 instruções
    no driver, mostra o objeto de driver, um IRP de PnP e o dispositivo dele
    na rotina IRP_MJ_PNP do driver, pede a parada com a máquina rodando,
    rastreia `kernel::ntos::ke::run_kernel_tasks` até o retorno (árvore com
    as chamadas), passa por cima e sai da função até o `kmain`, provoca o
    bugcheck 0xE2 pelo CrashOnCtrlScroll do i8042prt.sys real (teclas pelo
    monitor HMP), confere a análise e desenha a janela fora da tela.
  - Capturas: `opennt-dbg --launch --screenshot=ARQ --scenario=driver|trace|bugcheck`.
    O egui roda sem janela e um rasterizador de software (`offscreen.rs`)
    pinta os triângulos do `tessellate` com o atlas das fontes, sem GPU.
    `docs/screenshots/kd-gui.png` é o cenário `driver` (o mountmgr.sys real
    parado no retorno do IoCreateDevice),
    `docs/screenshots/kd-gui-rastro.png` o `trace` e
    `docs/screenshots/kd-gui-bugcheck.png` o `bugcheck`.
- **Depurador de engenharia reversa** (`tools/opennt-re`, binário `opennt-re`).
  - Uso: `cargo run -p opennt-re --release -- --launch` (com
    `--initial-process=smss` o csrss.exe real roda); `--connect=HOST:PORTA`;
    `--script=ARQ` roda um roteiro depois do attach.
  - Layout no estilo dos depuradores de engenharia reversa: abas no alto
    (CPU, Grafo, Log, Notas, Breakpoints, Mapa de memória, Pilha de
    chamadas, SEH, Script, Símbolos, Código-fonte, Referências, Threads,
    Handles, Rastro, Strings, Patches, Comentários/Rótulos, Processos,
    Exceção, Observação, Objetos do NT, Bugcheck), barra de comando e barra de estado
    (Pausado ou Rodando e a última mensagem). As abas são do `egui_dock`; o
    menu Exibir reabre uma aba e restaura o arranjo. Tema claro (padrão) e
    escuro.
  - Aba CPU: desmontagem (setas dos desvios, linha do RIP, instruções do
    último rastro, comentários e rótulos do usuário, marcadores, menu de
    contexto com Procurar), caixa de informação (operandos de memória com o
    valor, registradores lidos, destino), registradores com flags e
    segmentos, Dump 1-5 (hexadecimal com ASCII ou UTF-16, word, dword,
    qword, endereço, float, double; um byte editado vira patch) e pilha com
    os endereços de retorno nomeados.
  - Análise automática (`opennt_mcp::annotate`, a mesma da ferramenta
    `disassemble` do servidor MCP): os colchetes das funções na margem
    (`.pdata`, símbolo com tamanho ou o fluxo de código) e dos laços (até
    três níveis), do cache por função; os comentários automáticos das
    chamadas a APIs conhecidas, com os argumentos pelo preparo antes do
    `call` ou, na linha do RIP, pelos registradores e pela pilha de
    verdade; o nome vem do destino ou da entrada da IAT (`__imp_`); as
    strings referenciadas por operandos relativos ao RIP.
  - Nomes nos operandos (`disasm::disassemble_named`, um `SymbolResolver`
    do iced): o destino das chamadas e dos saltos para fora da função, os
    operandos relativos ao RIP e os imediatos que caem num módulo aparecem
    pelo símbolo (`call ntdll!NtClose`, `mov rax, qword ptr
    [win32kbase!gpsi]`), ou `módulo+0xRVA` sem símbolo; um slot da IAT
    aparece como o PDB o chamaria (`winlogon!__imp_NtClose`), pelos
    imports do PE (`imports.rs`: diretório 1 e o de carga adiada, 13). Os
    saltos dentro da função ficam com o endereço. Vale na CPU, no grafo,
    nas buscas e nas referências cruzadas.
  - Comentários do opennt-re (`annotations.rs`, depois dos do `opennt-mcp`):
    o import de cada `call`/`jmp [__imp_X]` e de cada trampolim, com o
    destino real do slot quando difere (a DLL de um API set, o
    `__imp_load_` de uma carga adiada pendente); o destino de um ponteiro
    de função global; o alvo das chamadas pelo CFG
    (`__guard_dispatch_icall_fptr`: o RAX montado antes, ou o de verdade
    na linha do RIP); os nomes de NTSTATUS e HRESULT nos imediatos de 32
    bits a partir de 0x40000000 e os erros do Win32 passados a
    `SetLastError` ou comparados depois de `GetLastError`; os campos dos
    tipos do PDB nos operandos de memória: `gs:` é a `_KPCR` no código do
    kernel da Microsoft e a `_TEB` no modo usuário, e um campo ponteiro
    lido passa o tipo ao registrador (`_KTHREAD` vira `_ETHREAD`,
    `_KPROCESS` vira `_EPROCESS`, `_NT_TIB` vira `_TEB`). O menu "Tipos do
    PDB" dá um tipo a um registrador a partir da linha (`rcx _EPROCESS`,
    `rbx win32kbase!tagWND`) e abre o operando de memória na aba Tipos.
  - Códigos de erro (`codes.rs`): os nomes saem do `ntstatus.h` e do
    `winerror.h` do SDK do Windows desta máquina (a versão mais nova em
    `Windows Kits\10\Include`, ou `OPENNT_SDK_INCLUDE`), com
    `HRESULT_FROM_WIN32` e `HRESULT_FROM_NT` montados; o texto sai das
    tabelas de mensagens do `ntdll.dll` e do `KernelBase.dll` (o `.mui`
    do idioma). Aparecem nos imediatos, na caixa de informação (o
    imediato e os registradores lidos) e no LastError/LastStatus da TEB.
  - Referências cruzadas (X ou Ctrl+R, `analysis.rs`): a análise do módulo
    inteiro numa thread, em lotes de 1024 funções da `.pdata` (os pedaços
    encadeados, UNW_FLAG_CHAININFO ou o bit 0 do UnwindData, ficam na
    função dona); sem `.pdata` (o `kernel.elf`), em faixas de 256 KB das
    seções de código. Cada lote guarda as referências ordenadas pelo
    destino (16 bytes cada): chamada e salto diretos, chamada e salto pela
    IAT, memória, `lea`, imediato no módulo e, no último lote, os
    ponteiros dos dados pela `.reloc` (vtables, tabelas de despacho). A
    janela responde com os lotes prontos e se refaz sozinha a cada décimo
    do total; mostra também a função do endereço (com o número de
    pedaços) e o que sai dela. A análise vale até um patch no módulo;
    ficam guardadas até seis.
  - Destaque (H, `highlight.rs`): o texto da instrução em pedaços; um clique
    num registrador ou operando marca as ocorrências na janela, com as
    partes do registrador (`eax` marca `rax`) e o número em qualquer
    grafia.
  - Registradores: XMM0-XMM15 (hexadecimal, floats, doubles), MXCSR, a
    metade alta dos YMM (indisponível quando o sistema não liga o AVX), x87
    e MMX, DR0-DR7, LastError e LastStatus da TEB e a caixa da convenção x64
    (`annotate::calling_convention_arguments`: RCX, RDX, R8, R9 e a pilha a
    partir de `[rsp+0x28]`, quantidade ajustável).
  - Menu de contexto da desmontagem: Breakpoint, executar até a seleção,
    nova origem (Ctrl+*), Seguir (desmontagem, dump, mapa de memória,
    grafo), Copiar (endereço, RVA, deslocamento no arquivo pela seção do
    PE, seleção, bytes, módulo+RVA), Binário (editar, preencher, NOP,
    montar), comentário, rótulo, marcador, referências e Procurar. Shift+
    clique seleciona várias linhas.
  - Editor de breakpoints (`editor.rs`, o modelo do formulário com a
    conferência): tipo, endereço, tamanho, nome, condição de parada, texto
    e condição de log, comandos e condição de comando, contagem de acertos,
    grupo, ligado, uma vez só, silencioso, retorno rápido e adiado. Sem
    condição de parada, um breakpoint com log só registra.
  - Observação: o valor que mudou desde a parada anterior em vermelho.
  - Dump (`dump.rs`): inteiros com e sem sinal de 1, 2, 4 e 8 bytes,
    float, double, ponteiro com símbolo e desmontagem; "sincronizar"
    desligado guarda o endereço de agora no lugar da expressão. Pilha: o
    comentário "retorno para X de Y" (Y é a função do quadro de baixo),
    presa ao RSP ou numa expressão.
  - Listas: Pilha de chamadas (Endereço, Para, De, Tamanho, Comentário,
    Parte), Threads de usuário (número, ID, entrada, TEB, RIP, RSP,
    suspensão, prioridade, estado, espera, LastError, tempos de usuário e
    de kernel, ciclos) e Mapa de memória (Endereço, Tamanho, Parte,
    Informação, Conteúdo, Tipo, Proteção, Proteção inicial; executável em
    vermelho; gravar a região num arquivo, página a página).
  - Servidor MCP na janela (menu Arquivo, `backend/mcp.rs`): uma thread
    atende HTTP em 127.0.0.1 e manda cada mensagem ao backend
    (`Request::Mcp`); o `opennt_mcp::Server` roda com a sessão da janela como
    `Engine`, e a janela relê a parada depois de cada ferramenta.
  - Backend (`backend.rs`, `backend/views.rs`): além do snapshot do
    `opennt-dbg`, monta o processo escolhido, os Dumps, a pilha, a caixa de
    informação, os argumentos dos quadros (o espaço de home e os primeiros
    da pilha), os tratadores de exceção (UNWIND_INFO, com a tabela do
    `__C_specific_handler`), o grafo, as buscas, o mapa de memória, os
    handles, as threads de usuário, os símbolos e imports de um módulo, os
    patches e os roteiros.
  - Imagens para as buscas (`opennt_kd::image`, reexportado em `scan.rs`): o PE desta máquina (cabeçalhos e
    seções nas RVAs) ou o `kernel.elf`; só o que não tem arquivo é lido do
    alvo. Os patches da sessão são aplicados por cima, e o cache de
    resultados por módulo vale até o próximo patch.
  - Montador (`asm.rs`): uma linha em sintaxe Intel; cada código do iced
    com o mnemônico é tentado com os operandos e fica a codificação mais
    curta. A instrução que sai é completada com NOP.
  - Notas: comentários, rótulos e marcadores em
    `<build>/opennt-re/notas.txt` (módulo + RVA), notas livres em
    `anotacoes.txt`; breakpoints em `breakpoints.txt`; o arranjo, o tema,
    o histórico e o roteiro em `%APPDATA%/opennt-re/estado.json`.
  - Teste de fumaça (`cargo test -p opennt-re --release -- --ignored`,
    `tests/smoke.rs`), sem janela, com `--initial-process=smss --smp=1`: para
    na carga do basesrv.dll no csrss.exe real (o evento de imagem), confere
    o contexto (PEB, módulos da PEB.Ldr com os símbolos da ntdll), para num
    breakpoint de usuário no ntdll!LdrLoadDll com a pilha até o CSRSRV, lê
    threads de usuário, handles e o mapa de memória, confere a aba Processos
    (a imagem do csrss, o PDB da ntdll, as pilhas de usuário e de kernel de
    uma thread), segue o csrss até a carga do winsrv.dll e para no ponto de
    entrada dele, monta o grafo de uma função do kernel e de uma da ntdll,
    acha referências conhecidas no ACPI.sys real (`PNP0A03` em ASCII e uma
    UTF-16) e no CSRSRV.dll, roda um roteiro e desenha a janela fora da
    tela.
  - Abas novas (`monitors.rs`, `explorers.rs`, `backend/extras.rs`): APIs
    (tabela virtual, filtros, detalhe, ir para o chamador, CSV), IRPs
    (lista e linha do tempo com as barras dos saltos), Tipos, Registro
    (árvore lida sob demanda e os valores), Objetos (árvore do namespace,
    consulta do NT e vista como tipo do corpo), Arquivos (pastas, prévia
    de 4 KB, cópia para o hospedeiro) e Snapshots (o modo, gravar, voltar,
    apagar, voltar um passo e voltar até o breakpoint). O monitor e os
    IRPs ficam num depósito (`MonitorStore`) que a janela lê sob a trava;
    a lista filtrada é refeita quando a geração ou o filtro mudam. O modo
    (`TimeMode`) sai das opções do `xtask` do alvo e aparece na barra de
    estado; o menu Arquivo reabre o alvo com snapshots, gravando ou
    reproduzindo. O Dump tem "Ver como tipo" (Ctrl+Shift+T).
  - Processos de usuário (`processes.rs`, `backend/usermode.rs`): a aba
    Processos tem a barra do contexto (kernel ou o processo escolhido, com
    sessão, CR3 e PEB; voltar ao kernel; o processo do CR3 da parada), a
    lista de processos com sessão, pai e imagem (o `_EPROCESS.Session`, o
    InheritedFromUniqueProcessId e o SeAuditProcessCreationInfo pelos tipos
    do PDB do ntoskrnl, lidos uma vez por processo; clique troca o
    contexto), os módulos do processo com entrada e o estado do PDB, o
    breakpoint de usuário com sugestões de símbolos, as threads de usuário
    com a pilha de usuário (o CONTEXT salvo) e a de kernel, e os eventos
    registrados (`cpr:*`, `epr:*`, `ld:*!` com log, sem parar).
  - Seguir (`follow.rs`): um plano `processo[!dll] [símbolos]` vira o
    breakpoint de evento `ld:processo!dll` (ou `cpr:processo`); na parada
    dele o backend troca o contexto para o processo, espera o PDB do módulo,
    arma os breakpoints de usuário só naquele processo e segue sozinho
    (`seguir dwm.exe!dwmcore.dll CD2DContext::InitializeD2D` na barra de
    comando). Os símbolos de módulos que ainda não carregaram esperam as
    cargas seguintes do processo (`ld:processo!`); os planos ficam em
    `<build>/opennt-re/seguir.txt`. Um breakpoint de usuário num módulo
    ainda não carregado vira um plano de uma vez só. Os símbolos de uma DLL
    saem do arquivo desta máquina e do PDB do cache, antes de o processo
    existir.
  - Aba Exceção (`exception.rs`): numa parada na entrada do
    KERNELBASE!RaiseFailFastException, do ntdll!KiUserExceptionDispatcher
    (o registro em RSP + 0x4F0), do RtlDispatchException, do
    RtlRaiseException, do NtRaiseException, do RtlReportException, do
    UnhandledExceptionFilter ou do RaiseException, o EXCEPTION_RECORD é lido
    e explicado: o código, as flags, o endereço, o sentido dos parâmetros
    (violação de acesso, o código do `__fastfail`, o HRESULT do fail-fast do
    MIL), as exceções guardadas do WinRT (STATUS_STOWED_EXCEPTION: HRESULT,
    thread, pilha ou texto de cada STOWED_EXCEPTION_INFORMATION e as
    aninhadas), o tipo lançado de uma exceção do C++ (pela ThrowInfo), os
    registros encadeados e a pilha desenrolada do CONTEXT. Numa parada de
    primeira chance (`uex`) o registro ainda não existe: o botão arma uma
    parada de uma vez só no KiUserExceptionDispatcher. Os breakpoints
    prontos (fail-fast, exceção não tratada, toda exceção entregue, saída
    com erro, erros do WinRT só com log) valem para o processo escolhido.
  - Preferências e banco por módulo (`preferences.rs`): fontes, escala,
    cores que trocam as da paleta, o editor de atalhos (as ações com a
    tecla, conflitos em vermelho) e as paradas em eventos (mandadas ao
    alvo na primeira parada e quando mudam), em
    `%APPDATA%/opennt-re/preferencias.json`. O banco por módulo
    (`<build>/opennt-re/db/<modulo>.json`) guarda comentários, rótulos,
    marcadores e breakpoints por RVA; é lido na abertura e gravado quando
    muda, e os breakpoints guardados são armados quando o módulo aparece.
  - Navegação e uso (`navigation.rs`, `status.rs`, `console.rs`,
    `copy_text.rs`, `layout.rs`): o histórico de idas da desmontagem por
    módulo + RVA (Alt+Esquerda e Alt+Direita, os botões laterais do mouse,
    o menu Navegar e os botões da barra de ferramentas); a janela Ir para
    (Ctrl+G) com a busca aproximada sobre todos os símbolos carregados (o
    índice que o backend publica a cada troca de módulos, procurado numa
    thread própria; uma tecla nova cancela a busca anterior), os rótulos e
    os marcadores, e o avaliador para o que parece expressão; os marcadores
    (Ctrl+M liga, F6 e Shift+F6 andam, a lista no menu Navegar); a lista dos
    atalhos (F1), e as teclas das preferências nos menus, nas dicas da barra
    de ferramentas e na barra de estado; a barra de estado com o estado do
    alvo (rodando há quanto tempo), a CPU, o IRQL, o processo, a thread, o
    modo, os PDBs que ainda estão chegando e a tarefa do backend com o
    tempo; o console embaixo (Ctrl+J: comandos ou eventos, filtro, cópia) e
    o log de eventos da janela (aba Log, Eventos); copiar qualquer aba como
    texto (Ctrl+Shift+C ou o botão direito no título da aba); a posição, o
    tamanho e o maximizado da janela (em pixels físicos), os painéis
    divisíveis e o arranjo das abas (lido à parte do resto, com as abas
    novas da versão) no arquivo de estado. A parada chega à janela antes do
    índice de símbolos; as listas grandes (Símbolos, Referências, o console)
    só são refiltradas quando a lista ou o filtro mudam; as comparações
    para gravar notas, preferências e estado rodam uma vez por segundo.
  - Testes de unidade (`cargo test -p opennt-re --release`): o destaque, os
    formatos do Dump, o modelo do editor de breakpoints, as colunas dos
    operandos, os formatos dos XMM, as preferências e o banco por módulo
    (ida e volta pelo disco), os imports e os trampolins, os
    `#define` do SDK e as tabelas de mensagens, a análise do módulo (os
    pedaços encadeados, a `.reloc`, os lotes), os caminhos dos campos
    dos tipos, o histórico, a busca aproximada (a nota, a ordem, o limite
    e a thread), os marcadores, a barra de estado, o transcrito em linhas,
    o log de eventos, a geometria da janela, o arranjo salvo de outra
    versão e a janela desenhada fora da tela com as janelas novas;
    os registros de exceção (violação de acesso, exceções guardadas do
    WinRT, `__fastfail`, C++, encadeados, as entradas conhecidas), o texto
    dos eventos do opennt-kd, a regra de casamento dos breakpoints de
    evento, os planos de seguir e o arquivo deles.
  - Fumaça das ferramentas (`tests/smoke_tools.rs`, `--ignored`): com
    `--start-driver=ntfs`, o monitor e o rastreador ligados no começo do
    boot, o IoCreateDevice do ntfs.sys com STATUS_SUCCESS, um
    IRP_MJ_CREATE concluído pelo \FileSystem\Ntfs, o `Current` de
    `SYSTEM\Select`, o ImageFileName do EPROCESS do System, o `\Driver`
    e a raiz do volume; com `--vm-snapshots`, um snapshot, três passos e a
    volta ao RIP de antes.
  - Capturas: `opennt-re --launch --screenshot-dir=docs/screenshots
    --scenario=kernel` grava `kd-re-cpu.png`, `kd-re-registradores.png`,
    `kd-re-breakpoint.png`, `kd-re-observacao.png`, `kd-re-grafo.png` e
    `kd-re-referencias.png`; `--scenario=usuario` grava `kd-re-usuario.png`,
    `kd-re-memoria.png` e `kd-re-referencias-usuario.png`;
    `--scenario=ferramentas` grava `kd-re-api.png`, `kd-re-irp.png`,
    `kd-re-tipos.png` e `kd-re-registro.png`; `--scenario=voltar` grava
    `kd-re-voltar.png`.
- **Servidor MCP** (`tools/opennt-mcp`, binário `opennt-mcp`).
  - Uso: `opennt-mcp` (stdio: uma mensagem JSON-RPC por linha na entrada,
    as respostas na saída, o log na saída de erro) ou
    `opennt-mcp --http=PORTA` (`POST http://127.0.0.1:PORTA/mcp`);
    `--root=DIR` troca a raiz do repositório.
  - Protocolo (`server.rs`, implementado no crate sobre o `serde_json`):
    `initialize` (versões 2025-06-18, 2025-03-26 e 2024-11-05; a pedida, se
    aceita), `ping`, `tools/list`, `tools/call`, `resources/list`,
    `resources/read`, lotes e notificações. Erros: JSON inválido -32700,
    pedido inválido -32600, método desconhecido -32601, ferramenta
    desconhecida ou argumentos fora do esquema -32602 (`tools::validate`
    confere tipos, obrigatórios, opções e limites); a falha de uma
    ferramenta volta no resultado com `isError` e o texto.
  - Transporte HTTP (`transport.rs`): só escuta em 127.0.0.1, recusa
    conexões de fora e um `Origin` que não seja local; `POST` devolve a
    resposta em `application/json` (ou 202 para notificações) com o
    `Mcp-Session-Id`; `GET` devolve 405 (sem fluxo SSE).
  - Ferramentas (`tools.rs`): `launch`, `connect`, `detach`, `status`,
    `break`, `go`, `wait_for_stop`, `step_into`, `step_over`, `step_out`,
    `run_to`, `registers_get`, `register_set`, `memory_read`,
    `memory_write`, `disassemble`, `symbol_lookup`, `symbol_resolve`,
    `modules`, `processes`, `threads`, `set_process`, `breakpoint_set`,
    `breakpoint_clear`, `breakpoint_enable`, `breakpoint_list`,
    `backtrace`, `search_strings`, `search_pattern`, `xrefs`, `nt_view`,
    `trace_start`, `trace_fetch`, `trace_stop`, `wait_for_serial`,
    `read_serial_log`, `run_script`, `command` e `screenshot`; e, em
    `tools_extra.rs`, `api_monitor_start|stop|fetch`,
    `irp_trace_start|stop|fetch`, `reverse_step`, `reverse_continue`,
    `snapshot_save|restore|list`, `view_struct`, `registry_list`,
    `registry_read`, `object_list`, `file_list` e `file_read`. Endereços
    são expressões em texto e os endereços dos resultados vão em texto
    (`0x...`). Cada resultado é um objeto (`structuredContent`) e o mesmo
    JSON em `content`. O argumento `process` aceita o nome (`dwm.exe`,
    `svchost.exe#2` = a segunda instância na lista do alvo), o PID ou o
    EPROCESS (`processes.rs`).
  - Ferramentas do fluxo dos agentes (`tools_flow.rs`):
    - `continue_until`: continua e espera o primeiro de: uma parada, um
      texto na COM1 (`marker`/`markers`, lidos só no que o log ganhou;
      `from_start` olha o log inteiro e, achando, volta sem continuar) ou
      o prazo (`break_on_timeout` para a máquina em vez do erro). Devolve o
      motivo (`breakpoint`, `event`, `stop`, `serial`, `timeout`), a
      parada, as linhas novas dos breakpoints de log e do DbgPrint desde a
      última entrega e os breakpoints adiados que armaram. O `launch` com
      `until_marker` faz o mesmo depois do attach;
    - `breakpoint_user`: breakpoint num processo de usuário pelo nome;
      com a DLL ainda fora do processo (ou o processo ainda não criado),
      fica adiado num breakpoint de evento `ld:processo!dll` e arma na
      parada desse evento (os módulos do processo relidos, o breakpoint
      gravado no processo), com a máquina seguindo sozinha;
      `continue_until`, `wait_for_stop`, `wait_for_serial` e `kd_script`
      atendem o aviso. O estado fica em `session.rs` (`Session`, dentro do
      `Server`);
    - `stack`: a pilha do processador da parada, de uma thread de kernel
      (`thread`) ou das threads de usuário de um processo (de usuário pelo
      CONTEXT salvo e de kernel pelo quadro de troca), agrupadas por pilha
      igual; cada quadro em uma linha `endereço símbolo`;
    - `memory_view`: bytes, words, dwords, qwords, pointers (com o
      símbolo de cada qword), ascii, unicode e unicode_string;
    - `kd_script`: os roteiros do `test-boot --kd=com2 --script` sobre a
      sessão, pelo executor do `opennt-kd` (`run_script_hosted`; o
      servidor é o anfitrião em `kdscript.rs`), com o log na resposta
      (nunca na saída padrão, que é o canal do stdio; as linhas dos
      breakpoints de log vão no `breakpoint_log`), as esperas dentro do
      prazo da ferramenta, o `wait-serial` no log da COM1 da sessão e o
      aviso de carga dos breakpoints de usuário adiados atendido nas
      esperas; `attach` não faz nada e `detach` é recusado. A linha que
      falha encerra com `ok=false`, `failed_line` e o log até ela.
  - Ferramentas de análise (`tools_analysis.rs`): `status_decode`
    (NTSTATUS, HRESULT com `HRESULT_FROM_WIN32`/`HRESULT_FROM_NT` e erros
    do Win32, pelos valores dos cabeçalhos públicos, em `status.rs`),
    `symbol_search` (trecho do nome em todos os módulos), `serial_summary`
    (`serial.rs`: marcadores `*_OK`, processos criados, blocos `[crash]` e
    `[kcrash]`, o código de parada, a presença do WdLog do dxgkrnl, as
    falhas agrupadas por padrão, as etiquetas e as últimas linhas, `grep`
    e `since_offset`), `crash_analyze` (o `!analyze` da parada e as quedas
    do log) e `wdlog` (a presença do despejo; a decodificação dos anéis é
    da análise do `opennt-kd`). As de log funcionam sem sessão com
    `path`.
  - Anotações (`tools_notes.rs`): `annotations_list` e `annotation_set`
    leem e gravam o `notas.txt` da sessão do opennt-re
    (`Engine::notes_file`, `<build>/opennt-re/notas.txt`) por módulo + RVA
    (o kernel do OpenNT é `kernel`); o `disassemble` mostra os rótulos e
    comentários do arquivo em `user_label` e `user_comment`.
  - Recursos: `opennt://serial-log`, `opennt://dbgprint`,
    `opennt://breakpoints` e `opennt://modules`.
  - Sessão (`engine.rs`): o trait `Engine` dá o cliente, o `launch`
    (`opennt_kd::launcher`), o `connect`, o log da COM1, o monitor do QEMU e
    o cache das imagens com os índices de referências cruzadas.
    `Standalone` é o do binário; a janela do opennt-re implementa o mesmo
    trait.
  - `screenshot` (`screenshot.rs`): `screendump` do monitor HMP do QEMU
    aberto pelo `launch`, em PNG; sem PNG no QEMU, PPM convertido para PNG
    no crate.
  - Testes (`cargo test -p opennt-mcp`): o protocolo (negociação, a lista de
    ferramentas com esquemas válidos, os erros, lotes), as ferramentas
    contra o alvo de mentira do `opennt-kd` (registradores estendidos,
    memória, desmontagem com o comentário da chamada ao IoCreateDevice,
    breakpoint de uma vez só, parada, pilha, símbolos, recursos, as
    ferramentas novas: o monitor com a chamada ao IoCreateDevice, o IRP de
    CREATE, o Registro, o namespace, os arquivos e os erros sem
    reprodução e sem monitor do QEMU; as dos agentes: o roteiro com
    `expect`/`save`/`$x`/`bp`/`c`/`wait-stop`, o roteiro que falha, o
    `continue_until` pelo texto já na COM1 e até o breakpoint, a memória
    em formatos, a pilha, os códigos de erro, o resumo do log, a queda, as
    anotações na desmontagem, a busca de símbolos e o erro do adiado sem
    o ponto de evento) e o
    binário em stdio; testes de unidade do decodificador de códigos, do
    resumo e da espera no log, dos nomes de processo e das trocas dos
    roteiros. Ponta a ponta (`cargo test -p opennt-mcp --release --
    --ignored`, `tests/e2e.rs`): o binário em stdio abre o OpenNT pelo
    `launch`, para, lê os registradores, arma um breakpoint em
    `kernel::ntos::ke::run_kernel_tasks`, continua até ele, confere a
    desmontagem e a pilha (`backtrace` e `stack`), tira o breakpoint,
    continua com `continue_until` até `[shell] pronto` na COM1 e resume o
    log (`OPENNT_MCP_BUILD_DIR` troca o build).
- **Teste do depurador**: o teste `kd` é um `test-boot` com
  `--kd=com2 --script=xtask/scripts/kd.txt`. O roteiro roda contra a COM2
  em paralelo ao boot e a falha dele derruba o teste. Passos:
  - anexa, confere o estado do depurador e os processadores congelados;
  - lê e grava memória; pede a parada com a máquina rodando;
  - para num breakpoint de software no laço principal; confere a saída do
    DbgPrint do ksecdd.sys real;
  - consultas do OpenNT: processos, threads, a pilha de uma thread de kernel
    bloqueada pelo quadro de troca até o ACPI.sys, módulos, processadores,
    `obj`, `k`, uma expressão e `!process`, `!thread`, `!drvobj \Driver\ACPI`,
    `!devobj` de um dispositivo dele e `lmv`;
  - o Registro vivo (`reg` em `SYSTEM\Select`), o namespace (`objdir
    \Driver`) e o monitor de APIs e o rastreador de IRPs ligados e
    desligados;
  - dá um passo; para num breakpoint de hardware;
  - rastreia 300 instruções a partir da entrada da função, mostra a árvore
    e rastreia até o retorno;
  - desliga; o boot segue até o shell, que o roteiro espera na COM1.

  O roteiro usa também a linguagem dos roteiros do kd: o breakpoint no
  laço principal tem log e um tratador que deixa a máquina seguir nos dois
  primeiros acertos e a para no terceiro; laços acham o System, a thread
  do ACPI.sys (conferida contra o `save-thread`) e o ksecdd.sys, e o
  `save-after` confere o EPROCESS do `!process 4` e a base do `lmv`.

  O teste `kd-parada` (`--script=xtask/scripts/kd-parada.txt`) cobre a
  robustez da parada com os autotestes do alvo (`monitor kdtest`, em
  `kd/self_test.rs`, que rodam no próximo tique do relógio do BSP no anel
  0): a parada por NMI com as interrupções desligadas (uma NMI do próprio
  BSP) e os quatro processadores congelados; uma exceção de usuário
  sintética pelo filtro na primeira chance (parando e seguindo) e na
  segunda; um comando que falta e um que chama KeBugCheckEx, abandonados;
  o passo sobre `hlt`; e uma #GP no meio de um passo, retomada pelo host
  pulando a instrução.

  O boot com `--kd` roda também `ntos/test/kernel_debugger.rs`
  (`KD_EXPORTS_OK`).
- **Marcadores**: `HELLO_KERNEL_OK`, `KERNEL_RS_OK`, `SELFTEST_OK`,
  `PHASE3_SELFTEST_OK` a `PHASE7_SELFTEST_OK`, `MULTIPROCESS_OK` (o
  NtCreateUserProcess de um processo pai real, na fase 7), `PIPES_OK` (o
  servidor e o cliente de pipes e mailslot pelos npfs.sys e msfs.sys reais,
  na fase 7, depois do `MULTIPROCESS_OK`), `JOBS_OK` (os jobs com
  processos de usuário reais, na fase 7, depois do `PIPES_OK`), `KBDTEST_OK`,
  `[shell] pronto`, `FILE_SYSTEM_MOUNT_OK name=<serviço>` (um arquivo do
  volume aberto e lido pelo file system real iniciado com `--start-driver`),
  `SMSS_CSRSS_OK` (com `--initial-process=smss`: o
  csrss.exe real criado pelo smss.exe real chega ao win32k;
  `cargo xtask test-boot SMSS_CSRSS_OK 300000 --initial-process=smss --build-dir=build/smss --smp=1`),
  `WIN32K_LOADED` (no mesmo boot: o win32k.sys real carregado pelo smss,
  com a tabela 1 e os callouts;
  `cargo xtask test-boot WIN32K_LOADED 420000 --initial-process=smss --build-dir=build/win32k --smp=1 --expect=SMSS_CSRSS_OK "--expect=thread GUI pelo PsConvertToGuiThread -> 0x0"`),
  `ADAPTER_STARTED` (com `--initial-process=smss --display=basic`: a sessão
  do win32k faz o dxgkrnl iniciar o adaptador do BasicDisplay, que
  habilita a interface de chegada de dispositivo de vídeo;
  `cargo xtask test-boot BASICDISPLAY_OK 600000 --initial-process=smss --display=basic --build-dir=build/win32k-display --smp=1 --expect=SMSS_CSRSS_OK --expect=ADAPTER_STARTED --expect=USER_INITIALIZED`)
  `USER_INITIALIZED` (o NtUserInitialize do csrss volta com sucesso,
  `initial_process::win32k_service_returned`; no mesmo teste) e
  `WINSTA0_OK` (o wininit.exe com as Desktops Winlogon e Default da
  WinSta0; ainda não sai: a Desktop Winlogon é criada, mas o
  NtUserCreateDesktopEx não volta, com o wininit e a RawInputThread
  esperando a resposta de mensagens à thread da Desktop do csrss);
  `USERMGR_STARTED` (um svchost.exe mapeia o usermgr.dll, o ServiceDll do
  UserManager; teste gerenciador-de-usuarios), `UMGR_USER_LOGIN` e
  `SIHOST_READY` (com `--conta-de-teste`: o svchost do UserManager publica
  o WNF_UMGR_USER_LOGIN e o WNF_UMGR_SIHOST_READY com o escopo da sessão
  do usuário, `initial_process::wnf_updated` chamado pelo
  NtUpdateWnfStateData de `ps/user/wnf.rs`; teste sihost),
  `USER_LOGON_OK`, `PROFILE_LOADED`, `USERINIT_STARTED` e
  `EXPLORER_STARTED` (com `--conta-de-teste`, observações de
  `initial_process.rs`: o token do logon interativo da conta entra no
  winlogon.exe da sessão 1, pelo NtDuplicateObject do lsass ou pelo atributo
  de handle ALPC do UserManager; o NTUSER.DAT desse usuário é montado em
  `\Registry\User\<SID>`; o winlogon.exe cria o userinit.exe e o userinit.exe
  cria o explorer.exe, os dois com o token desse usuário; testes
  logon-do-usuario, perfil-do-usuario, userinit e explorer; o teste
  area-de-trabalho espera o `DESKTOP_OK` da vigia da tela);
  `SHELL_TRAY_CREATED` (depois do `USER_LOGON_OK`, o NtUserCreateWindowEx do
  explorer.exe da sessão 1 volta com uma janela da classe Shell_TrayWnd, o
  nome lido pelo `LargeString` que o user32 passa no segundo argumento;
  `initial_process::win32k_window_created`), `SHELL_RESTARTED` (o
  explorer.exe que o winlogon.exe da sessão 1 cria com o token desse
  usuário depois do `EXPLORER_STARTED`, o shell recriado pelo
  WLGeneric_ShellRestart_Enter, cria a janela Shell_TrayWnd dele;
  `initial_process::shell_recreated`) e `STARTMENU_HOST_STARTED` (o
  StartMenuExperienceHost.exe nasce na sessão 1 com o token LowBox desse
  usuário); os testes barra-de-tarefas e menu-iniciar esperam também o
  `TASKBAR_OK` e o `START_MENU_OK` da vigia e do `--start-menu`, e o teste
  reinicio-do-shell, o segundo `DESKTOP_OK` da vigia depois do
  `SHELL_RESTARTED`;
  os de falha são `*** PANIC`, `*** EXCECAO`, `SELFTEST FALHOU` e `*** STOP`
  (a parada do KeBugCheckEx; com `--expect-stop` o STOP faz parte do teste,
  como no `bugcheck`). O `test-boot` procura falhas desde o boot até
  a última saída esperada e, com `--hold=MS`, por mais MS milissegundos;
  cada `--expect-any` é procurada desde o começo da serial, depois das
  `--expect`, em qualquer ordem. No `--keys`, `{combo}` vai ao `sendkey` do
  monitor (teclas pressionadas em ordem e soltas ao contrário, como
  `{ctrl_r-scroll_lock-scroll_lock}`), com cada nome conferido na lista dos
  que o `sendkey` do QEMU 11 aceita (`qemu::QEMU_KEYS`; a tecla do Windows é
  `meta_l`): o monitor só responderia `invalid parameter`, e o teste
  esgotaria o prazo sem a tecla.

## 6. Documentação e status

| Lugar | Conteúdo |
| --- | --- |
| `README.md` | o que é o OpenNT, estado por fase, como compilar, rodar e testar |
| `docs/ROADMAP.md` | fases e estado de cada componente; gerado por `cargo xtask status` |
| `docs/ARQUITETURA.md` | este documento |
| `docs/status/components.toml` | dados editados à mão: fases, componentes, testes, a lista `[[roda]]` e o `[marco]` |
| `docs/status/ntoskrnl-exports.def` | cache dos nomes exportados pelo `ntoskrnl.exe` 19045 |
| `docs/status/*.svg`, `docs/site/*.html` | gerados por `cargo xtask status`; não editar |
| `docs/site/capturas/<id>.png` | a tela do QEMU no fim de cada `[[teste]]`, gravada por `cargo xtask capturas` |
| `kernel/src/ntos/inc/types/nt_types.toml` | estruturas do NT que o `cargo xtask nt-types` gera do PDB do ntoskrnl |
| `docs/mapa-cadeia.md` | o que falta, por estágio, para a cadeia de modo usuário ir do services.exe à tela de logon, pela análise estática dos binários |

O site tem cinco páginas autocontidas (sem scripts, fontes nem imagens de
fora): Início, O que roda, Componentes, Exports e Testes. Na página O que roda,
cada `[[roda]]` é um binário da Microsoft (ou um marco) e o estado sai dos
dados: sem `teste`, Não roda; um teste com `espera_falha`, Parcial; senão o
componente do Windows cujo nome cita o binário decide (`implementado` = Roda,
outro estado = Parcial), e sem componente ou num marco, Roda. O campo `estado`
só existe onde os dados não dizem; o gerador avisa quando ele repete o que os
dados já dão, quando um Parcial não diz onde para (`para`) e quando um binário
de um componente testado não tem `[[roda]]`.

O `cargo xtask capturas` roda os `[[teste]]` com a máquina do `test-all` (um
build por configuração, pistas em paralelo) e passa a cada `test-boot
--no-build` o `--capture=docs/site/capturas/<id>.png`: o QEMU ganha um socket
QMP e, no fim do teste (passando ou não), o `screendump` grava a tela em PPM (o
QEMU desta máquina não tem a libpng), que o `xtask/src/png.rs` converte em PNG
sem moldura, com paleta e deflate próprio, abaixo de 60 KB, com a data e o
resultado nos textos do PNG; o `cargo xtask status` os lê de lá. Um teste
que passa com a tela de logon confirmada pela vigia do `--watch-screen`
(abaixo) grava como captura essa tela, a que o provou, mesmo se o QEMU já
terminou; uma tela de foto não cabe em 60 KB e vai pela metade (512x384).
Todo PNG que o test-boot grava leva no texto `opennt-tela` o tamanho da tela
que as conferências leram (1024x768): elas leem o `screendump` inteiro, nunca
o PNG, e quem confere um PNG de novo o amplia antes, pelo vizinho mais
próximo, para esse tamanho (o branco do relógio e o ponteiro são limites
absolutos que só valem na tela inteira).

O `test-boot --watch-screen` lê a tela durante o teste, pelo mesmo QMP, a
cada 2 s (`qemu::watch_screen`). Uma tela gráfica de pelo menos 800x600 com
64 pixels ou mais fora do preto, que não seja o fundo azul da tela de
bugcheck, põe no log da serial uma linha `[xtask] tela:` (quantos pixels, a
caixa que os contém e as cores mais comuns) e o marcador `FIRST_PIXEL_OK`, e
grava a tela em `<build>/primeira-tela.png`. A tela de texto da VGA (720x400)
e o aviso do QEMU antes da VGA iniciar (640x480) não contam. O vídeo de boot
do OpenNT (o modo VBE 1024x768) é todo preto, e o kernel só desenha nele a
tela de bugcheck: o que aparece ali vem de quem desenha depois do boot.

Depois do primeiro pixel e do `LOGONUI_STARTED` na serial (antes do LogonUI
nenhuma imagem cobrindo a tela é a de logon), a mesma vigia procura a tela de
logon (`screen_check::logon_screen`): um quarto ou mais da tela fora do preto,
pelo menos metade dos pares de pixels vizinhos desenhados com cada canal
mudando até 16 de um para o outro, 8 cores ou mais com 1/1536 da tela cada e
desenho (1% dos pixels) em 3/5 das linhas e 3/5 das colunas. Quando duas
leituras seguidas passam e diferem em até 1/32 dos pixels
(`screen_check::same_screen`), a segunda põe no log a linha `[xtask] tela de
logon` e o `LOGON_SCREEN_OK` e vai para `<build>/tela-de-logon.png`. Os
limites vêm da tela de bloqueio do 19041 numa instalação nova, o
`Web\Screen\img100.jpg` esticado para cobrir a tela de 1024x768, medida com a
imagem decodificada pelo WIC e por outros escalonamentos, com e sem o relógio
e a data: 35% a 51% fora do preto (a caverna da foto é escura), 84% a 94% dos
vizinhos suaves, 17 ou 18 cores, desenho em 84% das linhas e em 69% a 100%
das colunas. Não passam: a memória lida como cor (7% a 13% dos vizinhos
suaves), a cor de destaque com o relógio, que o LogonUI mostra sem a imagem
(2 cores), e um quadro rasgado ou uma faixa da imagem (menos de 3/5 das
linhas ou das colunas); um quadro rasgado mais perto do fim e a imagem
surgindo do preto não ficam iguais na leitura seguinte. O teste da tela de
logon que falha escreve no log o que faltou na última tela lida.

Num teste que espera o `DESKTOP_OK` (o marcador ou um `--expect`), a vigia
procura a área de trabalho em vez da tela de logon
(`screen_check::desktop_screen`), e só depois de o `EXPLORER_STARTED`
aparecer na serial. Embaixo, uma barra de 24 a 72 linhas contadas de baixo,
cada uma com 3/10 ou mais dos pixels escuros (nenhum canal acima de 0x80), e
2/5 ou mais da barra escura; acima dela, o papel de parede: 3/5 ou mais dos
pixels azuis (o azul pelo menos 32 acima do vermelho e não abaixo do verde),
metade ou mais dos vizinhos suaves, 8 cores ou mais com 1/1536 da tela, a
cor média de #0060B0 a #30C0FF e o verde médio da metade esquerda pelo menos
24 acima do da direita. Duas leituras seguidas iguais põem no log a linha
`[xtask] area de trabalho` e o `DESKTOP_OK` e vão para
`<build>/area-de-trabalho.png`. Os limites vêm do papel de parede padrão do
19041, o `Web\Wallpaper\Windows\img0.jpg` do perfil Default em modo
Preencher (com a tela de 1024x768, o
`CTranscodedImage::_CheckSystemWallpaperForBestMatch` do shell32 troca pelo
`Web\4K\Wallpaper\Windows\img0_1024x768.jpg`), decodificado pelo GDI+ nos
dois tamanhos: 99% dos pixels azuis, 99% dos vizinhos suaves, 204 a 320
cores, média de #0287E4 a #038EEA e verde médio de 166 ou 167 à esquerda e
de 105 a 117 à direita. O canal mais forte de cada pixel do img0 vai de 169 a
255, então o papel de parede nunca conta como barra. A barra modelada de 40
linhas (opaca #101010 ou #202020, ou #202020 translúcida de 55% a 85% sobre
o papel de parede, com a caixa de busca clara de 344 colunas ou sem ela, em
800x600, 1024x768 e 1280x800) fica com 56% a 93% dos pixels escuros. Não
passam: a tela de bloqueio (26% azul, e o chão escuro da caverna dá
centenas de linhas escuras embaixo), a cor de destaque com texto (a animação
do primeiro logon e o Bem-vindo), a área de trabalho sem a barra ou com o
fundo preto do perfil (o papel de parede que não carregou), a imagem
surgindo do preto, a memória lida como cor e um quadro pela metade. O teste
da área de trabalho que falha escreve no log o que faltou na última tela
lida.

Num teste que espera o `TASKBAR_OK`, a vigia segue depois do `DESKTOP_OK` e,
com o `SHELL_TRAY_CREATED` na serial, confere a barra de tarefas
(`screen_check::taskbar_layout`), com todas as medidas em função da altura h
da faixa escura de baixo (40 linhas a 96 DPI; o tamanho dos elementos da
barra segue o DPI, não o da tela): nos primeiros 6h/5 pixels, o logotipo
claro do Iniciar, de h/4 a 3h/5 pixels de lado e de h²/20 a 7h²/20 pixels;
nas 6h colunas da direita, o relógio, o grupo de colunas com texto mais à
direita (grupos separados por mais de max(h/5, 3) colunas vazias) com duas
linhas de h/8 a h/2 linhas cada, de h a 4h colunas. Um pixel é de texto
quando a luminância (2R+5G+B)/8 passa a mediana da barra por 0x60, na barra
opaca ou translúcida sobre o img0; o indicador de idioma, também em duas
linhas, fica à esquerda do relógio, e os ícones da área de notificação têm
uma linha só. Uma leitura com a barra vira a referência; o `TASKBAR_OK` sai
quando uma leitura seguinte tem a linha da hora mudada em max(h²/100, 4)
pixels ou mais, o resto da barra em até 1/20 e a tela acima em até 1/32
(`screen_check::clock_ticked`: o relógio passou de minuto, o caminho do
SetTimer, da repintura e do dwm, não um quadro congelado), e a leitura
seguinte é igual; a tela vai para `<build>/barra-de-tarefas.png`.

Num teste que espera o `SHELL_RESTARTED` (o explorer.exe recriado pelo
winlogon.exe criou a barra de tarefas), a vigia segue depois da área de
trabalho (e da barra, se o teste a espera) e confirma a área de trabalho de
novo (`qemu::restart_step`), com a mesma conferência da primeira, só em
leituras feitas depois do marcador: a leitura em que ele aparece pode ser de
antes dele e não conta. A barra do explorer que saiu já foi destruída quando
o novo cria a dele, então ela não passa por esta conferência. Duas leituras
seguidas iguais põem no log a linha `[xtask] area de trabalho de volta` e o
`DESKTOP_OK` de novo, e vão para `<build>/area-de-trabalho-reiniciada.png`.
O teste que falha depois da primeira área de trabalho escreve no log o que
faltou (o marcador ou a tela).

O `test-boot --capture-every=SEGUNDOS` grava a tela durante o teste em
`<build>/tela-NNNN.png` (`qemu::FrameSeries`): a NNNN é a dos NNNN×SEGUNDOS
segundos desde a subida do QEMU, e a tela igual à última gravada não é gravada
de novo, então um número que falta na sequência é uma tela que não mudou. A
tela vai inteira, sem cortar a moldura, e só a que passa de 256 KB é reduzida
pela metade. No fim do teste, passando ou não (prazo esgotado, STOP), a tela
vai para `<build>/tela-final.png`; se o QEMU já terminou, vai a última tela
lida. Os textos de cada PNG levam a hora da leitura e as últimas linhas da
serial naquele instante, e os da tela final também o resultado do teste. As
telas de uma execução anterior saem quando a série começa. O QMP atende um
cliente por vez: a vigia da tela e a série dividem uma thread
(`qemu::screen_thread`), e uma leitura serve às duas quando elas vencem juntas.

O test-boot também manda entrada como uma pessoa na frente da máquina, pelo
monitor HMP do QEMU, que o convidado recebe pelo teclado e pelo mouse PS/2 do
i8042 (o i8042prt.sys, o kbdclass.sys e o mouclass.sys reais, lidos pelo RIT
do win32k). Cada opção espera um marcador na serial (o do teste ou um
`--expect`) e um atraso, `MARCADOR[+MS]`, e age uma vez, na primeira
chegada dele, na ordem da linha de comando (`qemu::InputSend`); as telas que elas conferem são lidas pelo `screendump`
do próprio monitor, porque o QMP pode estar com a vigia. O `--send=...:TECLAS`
digita as teclas, na sintaxe do `--keys` (o `{clique}` aperta e solta o botão
esquerdo do mouse onde o ponteiro estiver), e põe no log a linha `[xtask]
teclas enviadas pelo monitor`. Cada ação abre a própria conexão do monitor e a
fecha no fim, porque o QEMU atende um cliente por vez. O `--dismiss=...:TECLAS` espera, por até 180 s,
a tela de bloqueio parada em duas leituras seguidas, com o relógio e a data
(500 pixels brancos ou mais nas 2/5 de baixo e nas 3/5 da esquerda da tela,
`screen_check::lock_screen_shown`), digita as teclas e espera, por até 60 s, a
tela seguinte parada em que a metade ou mais dos pixels mudou, o relógio saiu
(1/10 ou menos daqueles pixels brancos) e a tela continua desenhada, sem ser a
de bugcheck (`screen_check::lock_dismissed`): a tela de bloqueio subiu e
mostrou a de credenciais, e o log ganha o `LOGON_DISMISS_OK`. O
`--mouse=...:DX,DY` espera a tela parada e desenhada (um quarto ou mais fora
do preto, sem ser a de bugcheck: não o vídeo de boot com o ponteiro), anda
o mouse (DX, DY) em dez `mouse_move` e lê a tela por até 15 s, até achar entre as mudanças um grupo
do tamanho do ponteiro com a seta (miolo branco e contorno preto) só antes e
outro só depois, deslocado no sentido do movimento
(`screen_check::cursor_moved`; a aceleração do Windows muda a distância), e
o log ganha o `CURSOR_MOVED_OK`. A seta é achada pela forma dentro de cada
mudança (`screen_check::arrows_in`: um miolo branco fechado pelo contorno
preto, metade ou mais dos pixels em volta dele pretos, em até 40 pixels de
lado; conta como preto a luminância até 0x30, porque o contorno do cursor do
19041 tem alfa e sobre o azul do img0 mede de #000E21 a #002946, e a sombra
suave em volta, de #005E91 para cima), não pelo tamanho da mudança: o controle que se acende sob o ponteiro
(o botão de energia do LogonUI, 48x48) muda junto em volta da seta, e a seta
que anda pouco deixa os dois lugares numa mudança só. O
`--start-menu=...:TECLAS` espera a área de trabalho com a barra parada,
digita as teclas (`{meta_l}`, a tecla do Windows), espera o menu aberto e
parado e aperta o Esc até a tela de antes voltar
(`screen_check::start_menu_open`, com h da barra da tela de antes: a barra
muda em até 1/8; acima dela, o maior grupo de mudanças fica colado à esquerda
e à barra, tem 6h por 6h pixels ou mais, 3/4 deles mudados, de 1/200 a 1/2 de
texto e ícones longe da mediana por 0x60 e a maioria dos vizinhos suaves; fora
dele, a tela muda em até 1/32), e o log ganha o `START_MENU_OK`. O
`--start-click=...:X,Y` abre o menu como uma pessoa com o mouse: espera a
área de trabalho com a barra parada, leva o ponteiro ao botão Iniciar no
ponto (X, Y) como o `--context-menu` abaixo (`qemu::point_at`), toma como
tela de antes a tela parada com o ponteiro sobre o botão (a altura da barra
vem da leitura de antes do ponteiro, que sobre o logotipo entraria na
medida dele), aperta e solta o botão esquerdo e confere o menu aberto e o
Esc com as mesmas medidas do `--start-menu` (`qemu::start_menu_shown`,
`screen_check::start_menu_open_over`); o log ganha o `START_MENU_OK`. O
`--context-menu=...:X,Y` espera a tela desenhada parada, leva o ponteiro ao
ponto (X, Y) (`qemu::point_at`) e aperta o botão direito (`mouse_button 2`).
O mouse PS/2 é relativo e a aceleração do Windows muda a distância com a
velocidade, então o ponteiro vai como a mão olhando a tela: oito
`mouse_move -250 -250` o param no canto de cima à esquerda, onde a seta é
achada parada (`screen_check::pointer_near`, a ponta da seta é o canto da
caixa dela), e cada correção anda até 120 mickeys, em pacotes de até 2 a
cada 15 ms, pelo ganho medido na correção anterior em cada eixo; a seta que
chegou é achada entre as mudanças da tela (`screen_check::pointer_moved`:
um desenho parado parecido com a seta, como um ícone claro da barra de
tarefas, não conta) quando duas leituras seguidas, a 250 ms uma da outra, a
acham no mesmo lugar (o ponteiro desenhado anda depois do mouse), até a
ponta ficar a 2 pixels do ponto, em até 24 correções. Depois espera o menu
aberto e parado e aperta o Esc até a tela de antes voltar
(`screen_check::context_menu_open`: o maior grupo de mudanças começa a até
12 pixels do clique, tem de 80x40 a 600x700 pixels, 3/4 ou mais claros, de
1/500 a 1/5 de texto escuro em duas linhas ou mais, e fora dele a tela muda
em até 1/64; o menu do 19041 na área de trabalho mede 187x127, 91% claro e
1% de texto escuro em 3 linhas), e o log ganha o `CONTEXT_MENU_OK`.

Três entradas abrem um programa como uma pessoa e conferem a janela dele na
tela (`screen_check::window_opened`, por até 90 s, em duas leituras seguidas
iguais): acima da barra de tarefas, que pode mudar (o botão da janela nova),
o maior grupo de mudanças tem 240x160 pixels ou mais, 3/4 deles mudados, e
nas 30 linhas de cima a barra de título do tema claro do 19041 (metade ou
mais dos pixels claros e 1/500 ou mais escuros: o título e os botões); fora
dele a tela muda em até 1/8 (o ícone que ficou
selecionado). O log ganha o `WINDOW_OPENED_OK`. O `--double-click=...:X,Y`
leva o ponteiro a (X, Y) como o `--context-menu` e aperta duas vezes o botão
esquerdo, dentro do tempo do clique duplo do Windows (os quatro
`mouse_button` a 40 ms um do outro). O `--run=...:COMANDO` aperta Win+R,
confere a caixa Executar (uma janela nova), digita o comando, espera a
tela parada com ele e, depois do Enter, confere a janela do programa contra
a tela de antes do Win+R, numa tela diferente da do comando digitado (a
caixa Executar parada seria a janela nova). O
`--open=...:TECLAS` digita um atalho (`{ctrl-shift-esc}`, o Gerenciador de
Tarefas) e confere a janela nova. O `--type=...:TEXTO` digita letras,
algarismos e espaços na janela que tem o foco e espera a tela parada com
uma linha de texto (`screen_check::text_typed`: acima da barra, a tela muda
em até 1/20, e algum grupo de mudanças tem de 8 a 48 linhas de altura, 6
colunas ou mais por caractere, metade ou mais no fundo, a até 0x20 da
luminância mediana do grupo, e 1/100 ou mais de letras, a 0x60 ou mais
dela: o texto escuro do Bloco de Notas e o claro do console), e o log ganha
o `TEXT_TYPED_OK`. O `--command=...:COMANDO` digita o comando (letras,
algarismos e espaços) no console que tem o foco, espera a linha dele como o
`--type`, aperta Enter e espera a tela parada com a saída
(`screen_check::command_output`: acima da barra a tela muda em até 1/8, e
abaixo da linha do comando, onde o cursor que pisca não conta, há duas
linhas de texto ou mais, a mais larga com 6 colunas por caractere para 12
caracteres ou para o comando e mais um: o que o comando escreveu e o
prompt seguinte), e o log ganha o `COMMAND_OUTPUT_OK`. As janelas dos programas
também saem do kernel, como observação (`init/initial_process.rs`,
`program_window_created`): o primeiro NtUserCreateWindowEx de cada programa
da sessão 1 com a classe da janela principal dele põe na serial o
`EXPLORER_WINDOW_CREATED` (a CabinetWClass do explorer.exe), o
`NOTEPAD_WINDOW_CREATED` (a Notepad do notepad.exe), o
`CONSOLE_WINDOW_CREATED` (a ConsoleWindowClass do conhost.exe) ou o
`TASKMGR_WINDOW_CREATED` (a TaskManagerWindow do Taskmgr.exe); a primeira
lista de processos que o Taskmgr.exe recebe do NtQuerySystemInformation
com o próprio registro e o de outro processo com WorkingSetPrivateSize (a
coluna Memória) diferente de zero dá o `TASKMGR_PROCESS_MEMORY_OK`
(`process_list_returned`). Uma entrada
de tela que não vê a tela mudar como esperado encerra o teste com o que
faltou na última leitura.

O Ctrl+Shift+Esc segue o caminho do 19041 (teste gerenciador-de-tarefas):
a tecla de atalho que o SetWinlogonHotKeys do win32kfull registra (id 4)
chama o WinlogonHotkeyCallback, que manda o PostWinlogonMessage(0x404, 4)
ao winlogon; o WLGeneric_AppLauncher_Enter cria o `launchtm.exe` na sessão
do usuário, e ele abre o Taskmgr.exe pelo ShellExecuteExW. O Taskmgr.exe
lê a lista de processos pela SystemProcessInformation (a memória de cada
processo na aba Processos, que o teste abre com Alt+D) e consulta os
contadores de processador pelo pcwum.dll e o `\Device\PcwDrv`
do pcw.sys, que no boot do processo inicial real é driver de boot, como na
instalação. Quando o pcw.sys liga a extensão, o ExpPcwHostCallback
(`ex/pcw.rs`) registra os conjuntos de contadores do próprio kernel que o
Taskmgr.exe consulta: Processor Information (`ex/processor_counter_set.rs`,
o ExProcessorCounterSetCallback com uma instância por processador, uma
por nó e a _Total, e os 0xc8 bytes do ExpQueryProcessorInformationCounters
tirados do tempo que `ke/processor_information` cobra de cada processador
e da KPRCB; a "% Processor Utility" dá o CPU total da aba Processos) e
FileSystem Disk Activity (`fsrtl/volume_support.rs`, a soma dos
KPRCB.FsCounters). O CPU de cada processo vem dos tempos da lista de
processos. Os outros conjuntos do 19041 (Synchronization,
SynchronizationNuma, Thermal Zone Information e os dois do ETW) ainda não
são registrados.

## 7. O nome OpenNT nos arquivos

Banners, prompt do shell (`OpenNT> `), mensagens do `xtask`, rótulo do volume
em memória, arquivo de paginação (`/$opennt-pool-page-N.sys`) e as variáveis
de build (`OPENNT_WINDOWS_BINARIES`, `OPENNT_TRACE_SYSCALLS`, `OPENNT_VGK_SYS`)
usam o nome OpenNT. Continuam iguais: os marcadores de boot, o nome do binário
`kernel`, os artefatos `build/kernel.elf`, `kernel.pe` e `os.img` e os nomes
dos pacotes (`kernel`, `boot`).

## 8. Pontos em aberto

- Segurança dos objetos: só os objetos do ObCreateObject guardam o descritor
  no OBJECT_HEADER.SecurityDescriptor; os demais (processos, threads,
  tokens, objetos de despacho, namespace, seções) o guardam no registro do
  dono como `SecurityPolicy`, convertida de e para os componentes do
  descritor. O rótulo de confiança de processo (SYSTEM_PROCESS_TRUST_LABEL)
  não é aplicado: sem processos protegidos nenhum token tem TrustLevelSid, e
  o smss.exe (WinTcb no NT) perderia a escrita no \KnownDlls. A criação
  num diretório já existente confere o DIRECTORY_CREATE_OBJECT, mas o
  criador recebe o acesso pedido ao objeto novo sem verificação, como no
  ObInsertObject. A avaliação não interpreta as ACEs de callback de objeto
  nem listas de tipos de objeto, não audita e não monta o PRIVILEGE_SET dos
  privilégios usados. A verificação de travessia (ObpCheckTraverseAccess)
  não é feita: todos os tokens do OpenNT têm SeChangeNotifyPrivilege, com o
  qual o NT também a pula. Os diretórios criados pelo kernel no boot têm o
  descritor fixo de `se/object_security.rs` (SYSTEM e Everyone), não os
  do ObInitSystem/smss.
- Alguns grupos de exports ainda misturam componentes e moram no `exports.rs`
  de um só: `driver_helpers`, `io_diagnostics` e `x86bios_sleep_misc` em `io`
  (os handlers dos x86Bios* deste já moram em `hal/exports.rs`, mas os nomes
  seguem no grupo da ABI), `ke_ex_sync` em `ke`, e rotinas Se*/Ke* que
  ficaram em `ps`. Falta separá-los pelo prefixo, conforme a seção 3.1.
- `rtl/` (suporte do kernel em Rust) e `ntos/rtl/` (a Rtl do NT) ainda têm o
  mesmo nome.
- `ntos/ps/user/` reúne os serviços Nt* do modo usuário; no NT cada serviço
  mora no seu componente (NtCreateFile no Io, NtAllocateVirtualMemory no Mm).
- Nome do binário: manter `kernel` ou gerar `ntoskrnl.exe`.
- Gravação e reprodução do depurador (`--record`/`--replay`): no QEMU 11.1
  desta máquina, a gravação a partir do reset fica no carregador de boot
  (as leituras ATA PIO por consulta com IF=0 do `boot/src/stage2.s` só
  andam a cada checkpoint da gravação: 10 minutos sem chegar ao kernel), o
  `-loadvm` de um snapshot feito fora da gravação derruba o QEMU
  (`replay_advance_current_icount`) e, na reprodução, o `s` do gdbstub não
  volta com as flags padrão e derruba o QEMU com `qqemu.sstep=1`; o
  continuar, a parada pedida e o `qSupported` com `ReverseStep+` e
  `ReverseContinue+` funcionam. Os passos para trás estão no cliente, na
  janela e no MCP (conferidos contra o alvo de mentira); os snapshots
  (`--vm-snapshots`) são hoje o jeito de voltar a um ponto do kernel.
