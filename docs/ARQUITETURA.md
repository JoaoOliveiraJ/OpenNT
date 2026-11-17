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
| `tools/kd-client` | o cliente do depurador do kernel, só com a biblioteca padrão: protocolo remoto do GDB, símbolos (`kernel.elf`, exports dos PEs, PDBs públicos com cache e download), pilha pela `.pdata` e pelos frame pointers, tipos do PDB do ntoskrnl, expressões, breakpoints, rastro de instruções e os comandos de texto; usado pelo `xtask` e pelo `kd-gui` |
| `tools/kd-gui` | `opennt-dbg`, o depurador gráfico (egui/eframe, painéis do `egui_dock`, desmontagem do iced-x86, linhas e variáveis do DWARF pelo `addr2line`/`gimli`); as dependências dele não entram no build do kernel nem do `xtask` |
| `tools/kd-re` | `opennt-re`, o depurador de engenharia reversa (layout no estilo dos depuradores de engenharia reversa) para o kernel e os processos de usuário, sobre o mesmo cliente; as dependências dele também ficam fora do kernel e do `xtask` |
| `tools/kd-mcp` | `opennt-mcp`, o servidor do Model Context Protocol para agentes de IA (JSON-RPC 2.0 por stdio ou HTTP local), sobre o mesmo cliente; também a desmontagem e a análise automática que o `opennt-re` usa |

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
| 0xFFFF8080_00000000 | 257 | banco de PFNs nativo (MmPfnDatabase) |
| 0xFFFFA000_00000000 | 320 | pool executivo, PTEs de sistema dos MDLs (0xFFFFA001_40000000..0xFFFFA001_80000000), dump, memória contígua e independente, visões de sistema, VirtualAlloc de kernel, VAs globais das sessões (0xFFFFA006_80000000), pilhas de kernel das threads (0xFFFFA007_00000000..0xFFFFA008_00000000) |
| 0xFFFFB000_00000000 | 352 | **mapa direto**: toda a faixa física [0, 4 GB) em `DIRECT_MAP_BASE + PA` |
| 0xFFFFC000_C0000000 | 384 | **janela do heap**: heap do kernel (kmalloc, o alocador do Rust) e a arena dos convidados (IRPs, DEVICE_OBJECTs, MDLs, ExAllocatePool2...) sobre os frames de 32 MB a 96 MB |
| 0xFFFFF780_00000000 | 495 | KUSER_SHARED_DATA (visão do kernel) |
| 0xFFFFF800_00000000 | 496 | KPCR, pool de dados, a **imagem do kernel** (0xFFFFF800_40000000), a pilha de boot (topo em 0xFFFFF800_41200000) e a janela de imagens de kernel (0xFFFFF801_00000000..0xFFFFF802_00000000) |
| 0xFFFFF900_00000000 | 498 | **espaço de sessão**: tabela de topo própria de cada sessão (vazio na raiz do System e dos processos sem sessão); SessionCore, VA dinâmica (pool de sessão) e imagens de sessão |

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
tabelas fixas em 0x83000-0x8DFFF (PDPT, PD e nove PTs). A pilha de boot é
outra VA de sistema na mesma PD: 383 páginas RW e NX terminando em
`BOOT_STACK_TOP`, sobre os frames logo abaixo de 20 MB (a imagem pode ir até
17,5 MB, nos frames de 1 MB a 18,5 MB), com uma página de
guarda sem mapeamento embaixo (PT em 0x8E000). O stage2 carrega o GDTR pela VA
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
as filas prontas, a NextThread e o lock delas são os da KPRCB do processador
que despacha as threads (o de boot, no M0), de onde quer que venha a
prontidão. No M0 só o BSP executa o anel 3
(assert em `exec_user_mode`/`exec_user_context`); os APs têm KPCR e bloco,
mas não têm TSS, LSTAR nem pilha reserva. O autoteste
`ntos/test/multiprocess/per_cpu.rs` confere os blocos distintos de cada CPU
e uma syscall de teste que devolve gs:[10h] igual ao RSP do usuário.

**Thread corrente por CPU.** Como no NT, a thread corrente é a
KPRCB.CurrentThread da KPCR de cada processador: `ps::process::
get_current_thread` (o KeGetCurrentThread, e por ele PsGetCurrentThread,
PsGetCurrentProcess e os demais que partem da thread corrente) lê gs:[188h]
da CPU que executa, e `set_current_thread`, o ponto único de troca de
thread, grava só a célula da própria CPU (`pcr::set_current_thread`, pelo
GS) antes de carregar a raiz do processo dela. Não há célula global: uma
troca num AP não muda o que o BSP vê, e um AP que nunca trocou de thread
tem 0 (o contexto do System, como o BSP antes do escalonador). O autoteste
`ntos/test/multiprocess/current_thread.rs` põe cada CPU online, ao mesmo
tempo, numa thread de um processo de kernel só dela (os APs por um job,
entre duas barreiras): cada uma vê em gs:[188h] a própria thread, e dela o
próprio processo e TID, e o PsGetCurrentThread do BSP no meio da janela
devolve a dele.

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
RtlpCopyXStateChunk; o ntoskrnl 19041 não as exporta, as da ntdll são as que
o modo usuário usa), e `ps/context/xstate.rs` move o pedaço XSTATE entre a
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
STATUS_NOT_SUPPORTED; de KernelMode o CONTEXT_XSTATE continua recusado). O
frame das APCs de usuário segue sem o pedaço XSTATE: no 19041 ele só vem
numa APC especial com o flag do XSTATE ou numa thread com CET. Os
autotestes são `ntos/test/extended_state.rs` (fase 6, `XSTATE_KERNEL_OK`: a
configuração contra o CPUID de cada CPU, os exports, os salvamentos dos
drivers e duas threads de sistema com YMM diferentes) e
`ntos/test/multiprocess/extended_state.rs` (fase 7, `XSTATE_USER_OK`: duas
threads de usuário com AVX e a ntdll real, o NtGetContextThread com
CONTEXT_XSTATE e a volta de uma exceção pelo NtContinue).

**IPIs medidos em tempo.** Toda espera de resposta a um IPI (`ke/smp.rs`:
o ICR voltar a ocioso depois do envio e as confirmações do shootdown de
TLB) passa por `smp::stall_on_targets`, que compara o TSC (o contador do
KeQueryPerformanceCounter) com a frequência vezes o prazo, como a detecção
de IPI parado do NT, em vez de contar voltas: o prazo é o mesmo em qualquer
CPU, hipervisor ou emulador. Um processador que não confirma o shootdown em
5 s, ou um ICR que não fica ocioso em 100 ms, para o sistema com o
diagnóstico (os processadores pendentes, pelo número, e o tempo) e o
IPI_WATCHDOG_TIMEOUT (0x1DB) com os parâmetros do KiIpiGenericCallTarget do
19041: a frequência, o contador corrente e o do início da espera. A partida
dos APs (INIT/SIPI) usa o mesmo envio e devolve erro ao boot. O autoteste
`ntos/test/multiprocess/ipi_stall.rs` confere que uma resposta que chega
em 50 ms num prazo de 200 ms é aceita, que um alvo mudo é detectado depois
dos 30 ms do prazo, não antes, com contadores coerentes, e o shootdown real.
A confirmação do shootdown vem pela NMI, que nem o IF nem o IRQL (o CR8) do
alvo retêm: o mesmo autoteste faz um AP girar com as interrupções
desligadas em HIGH_LEVEL e confirma 64 shootdowns seguidos (na casa das
dezenas de microssegundos no TCG). Os 100 ms e 5 s valem em hardware e sob
hipervisor; num emulador (o TCG do QEMU, "TCGTCGTCGTCG" na leaf 0x40000000,
`hal::hypervisor::is_emulator`) valem 12 vezes mais: lá cada CPU virtual é
uma thread comum do hospedeiro, a entrega da NMI e o tratador dela passam
pela trava global do emulador, e com o hospedeiro carregado a thread de um
alvo fica segundos sem rodar, o que nada no convidado evita.

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
processos de kernel do escalonador, veja abaixo) e os níveis dos contextos
de KeAllocateCalloutStackEx. Como no KiSwapContext, o
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
aninha: a thread cede a vez. Uma thread em execução dada como pronta
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
cancela o timer, grava KTHREAD.WaitStatus e põe a thread na fila pronta. O
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
na fila para entregá-la na própria pilha. Os locks do Ex (fast e guarded mutex, ERESOURCE, push
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
alimenta). As demais esperas genéricas de
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
despachada nesta CPU (o BSP, no M0), rodando na própria pilha de kernel e
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
no anel 3; a syscall termina o intervalo como qualquer outra. Passam por aí
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
Uma thread terminada enquanto bloqueada tem a espera concluída com
STATUS_THREAD_IS_TERMINATING e é retomada para desfazer o serviço antes de a
pilha voltar ao Mm (uma aquisição continua até concluir, como a espera de um
mutex no NT); o término de um processo espera as threads dele desfazerem os
serviços. Os serviços Nt* que
esperam por handle (NtWaitFor*, NtDelayExecution) continuam com o modelo
PENDING + espera sondada, sem pilha suspensa. O NtWaitForSingleObject e o
NtWaitForMultipleObjects de modo usuário capturam o prazo e os handles e
resolvem os objetos pelo mesmo `ob/wait::reference_objects` do
ObWaitForMultipleObjects (tabela nativa, tabela de usuário, SYNCHRONIZE em
UserMode): o objeto de espera é o DefaultObject do tipo (o corpo dos tipos
com DISPATCHER_HEADER, o FILE_OBJECT.Event, a KQUEUE do IoCompletion, que o
WaitAll recusa com STATUS_INVALID_HANDLE) e, nos demais tipos, o
ObpDefaultObject (um evento de notificação sempre sinalizado); Count fora de
1..64 dá STATUS_INVALID_PARAMETER_1, WaitType além de WaitAny
STATUS_INVALID_PARAMETER_3, e um objeto repetido só é recusado no WaitAll
(STATUS_INVALID_PARAMETER_MIX). Os prazos dessas esperas sondadas contam em
ms arredondados para cima (um prazo não nulo abaixo de 1 ms espera o
próximo ms, nunca vence de imediato). O NtDelayExecution com intervalo zero,
sem Alertable e sem UserApcPending, é a troca do NtYieldExecution
(STATUS_SUCCESS ou STATUS_NO_YIELD_PERFORMED), como no
KeDelayExecutionThread. O NtSignalAndWaitForSingleObject referencia o
objeto a sinalizar sem direito e o de espera com SYNCHRONIZE, sinaliza pelo
tipo (`ob/wait::SignalObject`: evento com EVENT_MODIFY_STATE, mutant com a
posse, semáforo com SEMAPHORE_MODIFY_STATE e o limite, outro tipo
STATUS_OBJECT_TYPE_MISMATCH) e só então espera; a CPU de usuário é do
serviço até a espera ser instalada, então o par é atômico. O
NtAlertThreadByThreadId recusa a thread de outro processo (o KTHREAD.Process
dela contra o da corrente) com STATUS_ACCESS_DENIED, sem deixar o alerta
pendente. O autoteste
`ntos/test/multiprocess/blocking_wait.rs` roda duas threads de um processo
real no despachante: a 1 espera um KEVENT sem prazo numa syscall de teste e
a 2, que só fica pronta depois disso, a vê bloqueada (Waiting, KernelStack
dentro da pilha dela) e sinaliza o evento; a 1 volta na própria pilha com
STATUS_SUCCESS e devolve 0 ao anel 3. Um segundo cenário termina a thread
bloqueada (THREAD_IS_TERMINATING, desfeita na própria pilha). O autoteste
`ntos/test/multiprocess/queue_wait.rs` faz o mesmo com o KeRemoveQueue: a
thread que espera na fila fica parada (CycleTime constante) enquanto a
outra gira 50 ms e insere, e volta com a entrada; com prazo de 100 ms e
ninguém inserindo, volta com STATUS_TIMEOUT sem gastar a espera em ciclos;
no KeRemoveQueueEx alertável em UserMode, o NtAlertThread da outra a
interrompe com STATUS_ALERTED; nos três a vaga da fila volta.

**Despachante de todos os processos.** Um despachante só serve as threads
de usuário de todos os processos vivos (`ps/user/threads.rs`):
`dispatch_one` sonda as esperas de todas as threads dos processos que
entraram nele (`ProcessState.started`), roda o `pump_kernel` e os pumps de
ALPC, `device_io`, fábricas e pacotes de espera, retoma as threads
terminadas que precisam desfazer um serviço bloqueado, conclui os términos
adiados e dá um intervalo à thread de usuário pronta mais prioritária da
fila do `thread_dispatch`, de qualquer processo; a troca de thread corrente
carrega a raiz do processo dela. Um despacho aninhado (um pump dentro do
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
termina o alvo sem tocar em quem chamou. As threads do processo morrem na
hora (`threads::begin_exit`: esperas com THREAD_IS_TERMINATING, fora da fila
de prontas); o término (`finish_exit`: o post-mortem de um processo que
rodou, o `terminate_process` com as notificações no contexto de uma thread
dele e as rotinas de saída, e a liberação das threads) roda já ou, se uma
thread dele tem serviço suspenso no kernel ou o intervalo em curso é dele,
fica com o despachante, que o conclui depois de desfazer os serviços. O
NtTerminateProcess(NULL) termina as outras threads do processo corrente e
quem chamou segue, como o primeiro passo do RtlExitUserProcess. A troca de
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
o laço. Dentro do callback a thread continua escalonável, como no NT: os
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
  as criou. Os serviços agem sobre um `memory::Space`, o do processo do
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
  sem relocação, sem imports, sem cookie e sem a tabela de exports). Todas
  as seções do mesmo arquivo usam a mesma control area (a identidade do
  arquivo, o papel do ImageSectionObject); a seção e cada vista a retêm, e a
  última referência devolve os frames. A vista (`image_view.rs`, o
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

O stage2 monta o mapa direto (páginas de 2 MB de supervisor, RW e NX; tabelas
em 0x76000-0x7AFFF) antes de entrar no kernel. A regra:

- **Endereço físico nunca é ponteiro.** Quem tem um PA usa `hal::physical`,
  que traduz pelo mapa direto e para o sistema se receber algo fora da faixa
  física (uma VA, por exemplo). Isso vale para PTEs e tabelas (`paging.rs`),
  descritores de PFN, frames do PFN, MMIO (LAPIC, texto VGA), tabelas ACPI,
  o handoff do stage2 (E820, flags, firmware), as células fixas de baixo
  nível (0x81000 e a IDT em 0x82000) e os dados do trampolim dos APs. A
  IDT, a GDT do boot e as pilhas dos APs são carregadas
  pela VA do mapa direto; MmMapIoSpace e os mapeamentos físicos da HAL
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

**Heap do kernel e arena dos convidados.** Os frames de 32 MB a 96 MB (fora
do PFN) aparecem só na janela do heap, `KERNEL_HEAP_BASE + (PA - 32 MB)`, o
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
todo `Box`/`Vec` do kernel) e a arena de 16 MB reservada dele devolvem VAs
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
- **Drivers carregados por outro driver** (o KMDF): a WdfLdr.sys é um driver
  de export, carregado pelo `mm/sysload.rs` como biblioteca de import do
  cliente KMDF; o WdfVersionBind do cliente pede o ZwLoadDriver do serviço
  do runtime (Wdf01000), que sobe pelo mesmo ciclo de vida do SCM
  (`cm/service/driver.rs` → `io/lifecycle.rs`) aninhado no DriverEntry do
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
  GetRelatedDeviceInstance sobre a árvore de `devnode.rs`; os demais
  códigos conhecidos ainda respondem STATUS_NOT_IMPLEMENTED.
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
através da interface do barramento. IoGetDeviceProperty,
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
Os recursos de todos esses nós passam pelos árbitros e tradutores dos
drivers de barramento (`io/pnp/arbiter.rs`): o teclado recebe as portas
0x60/0x64 do árbitro do pci.sys e a IRQ 1 do árbitro do acpi.sys, com o
vetor que o tradutor dele dá. Os dispositivos sem driver na caixa ficam
sem instalação (CM_PROB_FAILED_INSTALL): a placa de rede e1000 (o driver
dela vem do repositório de drivers, nete1g3e.inf), a controladora de
disquete (fdc.inf), as portas serial e paralela (msports.inf; o serial.sys
tomaria a COM1, que é a saída do log do kernel), o fw_cfg do QEMU e o
processador (cpu.inf). O barramento PCI interno do kernel fica fora dessa
árvore; as funções dos drivers internos são reconhecidas pelos ids de
classe do pci.sys (`device_tree.rs`).

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
  despacha os Pcw* para ele), a autorização (id 2, o ksecdd.sys) e o BCrypt
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
  TokenIsAppContainer direto no ULONG de saída, sem alocar.
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
  token LowBox. Os exports (SeAccessCheck, SeAccessCheckFromState(Ex),
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
  VA de sistema, sem travar), o MmProbeAndLockPages (MDL_PAGES_LOCKED), o
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
  (Inserted, Running, Disabled). Os inseridos ficam numa fila do módulo
  (o papel das coleções de árvores do NT) que o pump dos timers expira:
  SignalState 1 (Timer2Notification/Synchronization nas esperas de
  `ke/dispatcher.rs`), periódico de volta para agora + Period e o callback
  em DISPATCH_LEVEL.
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
  estendidos e dados), Flush e Stop; EtwWrite/EtwWriteTransfer/EtwWriteEx/
  EtwWriteString e o NtTraceEvent 0x300 da ntdll entregam só às sessões
  cujo nível e keywords aceitam o evento. O NtTraceControl 24 (o
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
  43 códigos como o 19041; ficam sem implementação (STATUS_INVALID_DEVICE_REQUEST
  depois da validação) os consumidores de tempo real, o EnableTraceEx2 de
  modo usuário (17), as respostas a notificações, as listas de GUIDs e
  grupos, WDI, compressão e sessões privadas, que nenhum processo do boot
  usa; os grupos de provedores dos traits, os eventos de imagem do
  EtwTrackProviderBinary, os loggers clássicos por TRACEHANDLE (NtTraceEvent
  0x200) e os autologgers do Registro também não existem. Testes:
  `etw_trace_session` e `etw_user_registration` na fase 6; o marcador
  `ETW_USER_REGISTRATION_OK` no boot do smss real.
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
    chegou antes.
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
    `qXfer:libraries:read` dá a lista de módulos ao GDB.
  - Consultas pelo `qRcmd` (o `monitor` do GDB): `kd/monitor.rs` lista
    processos e threads pelas listas nativas, os registradores de uma thread
    fora da CPU pelo quadro de troca, módulos, processadores com IRQL e
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
    no passo comum. O formato é o de `tools/kd-client/src/trace.rs`.
  - Paradas (`kd/stop.rs`), pelos trampolins (`hal/amd64/irqstubs.rs`):
    `int 3` e #DB do anel 0 antes do SEH (o KiDebugRoutine); o tique do
    relógio no anel 0 consulta o LSR (o 0x03 do host, ou o começo de um
    pacote, para a máquina, como o KdPollBreakIn); a exceção sem tratador e
    o KeBugCheckEx param antes do diagnóstico e da tela de STOP; o pânico
    para antes de travar.
  - Congelamento: o processador da parada congela os outros com NMI
    pelo código de IPI do Ke (`smp::send_nmi_to_application_processors`; a
    NMI dos APs prende o processador em `rs_kd_freeze_processor` com o
    quadro publicado) e só os degela ao continuar.
  - Passo: roda só no processador da parada, com o IF mascarado durante a
    instrução. O IF original volta depois, e um `pushfq` passo a passo grava
    o IF original. Continuar de um breakpoint dá antes um passo com o byte
    original.
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
      físico: num quadro de código compartilhado (a ntdll), o `int 3` de
      outro processo é reconhecido pelo quadro físico
      (`breakpoints::classify_user_hit`) e passa sem parar, com o byte
      original de volta por um passo da thread. O passo e a saída de um
      breakpoint usam o TF no CONTEXT; o #DB do passo volta pelo mesmo
      caminho e é reconhecido pelo endereço do CONTEXT. `monitor uex on`
      para também nas outras exceções do anel 3. Antes de gravar num
      endereço de usuário, o byte atual é conferido. Os comparadores de
      hardware do depurador valem só no anel 0: na entrada do anel 3 a HAL
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
      argumentos.
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
  - Exploradores (`kd/explore.rs`): `reg keys|values|value` lê a arena do
    `cm/registry` (`node_by_path`, `with_node`, `hive_of`), seguindo os
    links; `objdir` lista um diretório do `ob/object_manager` (tipo, corpo
    nativo, filhos, destino do link ou arquivo); `fs ls|read` usa o leitor
    NTFS do kernel (`drivers/fs/ntfs::mounted`, ATA PIO por consulta).
    Todos alocam e tomam as travas do Rust: só rodam com
    `stop::locks_held()` falso. Saída paginada pelo tamanho (`mais: N`),
    campos separados por tabulação. A linha do `qRcmd` aceita 512 bytes.
  - Os APs ainda usam a própria IDT de três vetores: só o BSP trata
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
  `bugcheck`.
- **Pedidos térmicos** (`po/thermal.rs`, `po/reason_context.rs`): a
  extensão de resfriamento de cada alvo recebe a
  GUID_THERMAL_COOLING_INTERFACE por um IRP_MN_QUERY_INTERFACE síncrono ao
  alvo; o agregado dos pedidos (menor percentual, OU dos ativos) chama
  PassiveCooling/ActiveCooling do driver só quando muda, sem trava, e o
  último pedido devolve a interface. A extensão fica num registro por
  dispositivo (no NT, na DOPE do alvo).
- **Ações de energia** (`po/power_action.rs`): ZwInitiatePowerAction valida
  como o NtInitiatePowerAction; sem a política de energia
  (PopExecutePowerAction) as ações reais devolvem STATUS_NOT_SUPPORTED, e
  o PoShutdownBugCheck cai no bugcheck pedido. PoSetHiberRange só aceita
  um mapa fechado: o OpenNT não hiberna.
- **Informações de energia** (`po/power_information.rs`,
  `po/power_setting.rs`): o NtPowerInformation de modo usuário segue o
  19041 (níveis só de kernel recusados, privilégio para entrada fora da
  lista sem privilégio, entrada capturada, saída sondada e o fim comum de
  cópia); os níveis 4, 5, 58, 59, 66 e 75 têm o mesmo corpo de modo kernel
  e de usuário. O nível 4 é o PopCapabilities de um desktop S0/S5 (0x4c
  bytes, só o botão de energia, o S5, o FullWake e o DiskSpinDown) e o 5 é
  o estado composto sem bateria (AcOnLine). As configurações de power
  setting nascem do PopSetPowerSettingValue (no boot, o
  PopInitilizeAcDcSettings grava GUID_ACDC_POWER_SOURCE): o nível 58 cria
  no primeiro pedido o nome WNF temporário de escopo de máquina da
  configuração (ou o nome global, sem GUID; GUID desconhecido dá
  STATUS_NOT_FOUND) e o 59 serializa os valores AC, DC e Hot com os
  carimbos de mudança. Os valores ainda não são publicados nos nomes. O
  PowerInformationInternal 0x1F e 0x20 (o RtlGet/SetSystemBootStatus do
  ntdll) lê e grava o boot status data (`po/boot_status.rs`): os itens
  capturados e sondados, o arquivo `\SystemRoot\bootstat.dat` aberto pelo
  ZwOpenFile (ou o `OsBootstatPath` de `Control`), o acesso do chamador ao
  descritor dele, os campos do RtlpBootStatusFields pelo cache, o checksum
  ajustado no Set e o campo gravado no black box. O volume não tem o
  arquivo, então o pedido devolve o status da abertura.
- **Desligamento e reinício** (`po/shutdown.rs`, `io/shutdown.rs`,
  `ex/shutdown.rs`, `hal/firmware_return.rs`): NtShutdownSystem e o
  NtSetSystemPowerState das ações de desligamento, de modo kernel e de
  usuário (SeShutdownPrivilege habilitado), seguem o PopGracefulShutdown do
  19041: o PopShutdownEvent e as threads do PoRequestShutdownEvent,
  ExShutdownSystem(0) (o ShutdownTime em Control\Windows),
  IoShutdownSystem(0) (IRP_MJ_SHUTDOWN síncrono no topo da pilha de cada
  IoRegisterShutdownNotification, da cabeça para a cauda), CmShutdownSystem
  (as hives no disco), IoShutdownSystem(1) (os file systems das filas de
  disco, CD-ROM e fita, sob o IopDatabaseResource que não é mais solto, e
  a fila de última chance), CcWaitForCurrentLazyWriterActivity e o
  PopShutdownSystem, que vai ao HalReturnToFirmware: S5 pelo PM1x_CNT com
  o HalpShutdownContext do HaliAcpiMachineStateInit (sem o acpi.sys, do
  `\_S5_` da DSDT) ou o reinício (CMOS 0x0F, 0x472, RESET_REG, 8042). A
  política DontPowerOffAfterShutdown faz o ShutdownNoReboot parar sem
  desligar. Os passos de componentes que o OpenNT não tem (Tm, Etw, Mm sem
  paginação, os IRPs S5 aos dispositivos) ficam de fora. O shell tem
  `shutdown` e `reboot`; o `--shutdown-test` cobre o caminho inteiro com o
  ntfs.sys real (testes `shutdown` e `reboot`).
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
  primeiro, `\??\D:` e `\SystemRoot` (`...\Windows`) ao segundo; o nó do
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
  STATUS_INVALID_DEVICE_REQUEST. Teste: `kernel_volume_devices` na fase 6.
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
  tabela do System e valem em qualquer processo, só em KernelMode. Os valores
  novos vêm do espaço global de `ob/handle_ids.rs`, então um handle aberto ou
  duplicado nunca repete o valor de outra tabela; só a herança põe o mesmo
  valor no filho, como no NT. No término, a drenagem da HANDLE_TABLE nativa
  fecha cada handle pela tabela do processo dono, e `process_state::destroy`
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
    limitadas e THREAD_RESUME.
  - NtQueryInformationProcess(ProcessBasicInformation, ProcessImageFileName)
    lê o EPROCESS do handle (PROCESS_QUERY_LIMITED_INFORMATION): PEB, PID,
    InheritedFromUniqueProcessId, prioridade base e código de saída, ou o
    caminho da imagem do `ProcessState`; NtQueryInformationThread já lia a
    thread do handle (TEB e CLIENT_ID da ETHREAD).
  - Teste: `ntos/test/multiprocess/cross_handles.rs`.
- **Memória entre processos** (`ps/user/memory.rs`, `mm/copy_virtual.rs`):
  - NtAllocateVirtualMemory(Ex), NtFreeVirtualMemory e
    NtProtectVirtualMemory (PROCESS_VM_OPERATION) e NtQueryVirtualMemory
    (PROCESS_QUERY_INFORMATION) agem sobre o processo do handle
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
  cliente) até serem liberadas; os módulos do loader do kernel, com as
  imagens, ficam em `ProcessState` (a ntdll é do sistema e vale em todos).
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
- **Criação de processos**: um caminho só, `ps/create.rs::
  create_user_process` (o papel do PspCreateProcess/PspAllocateProcess com
  o PspAllocateThread e o PspInsertProcess/PspInsertThread). Todo processo
  de usuário nasce ali: o `run_windows_process` e o `run_service`
  (`ps/user/process.rs`, que só monta o pedido e executa o processo
  criado, `run_created` = `start_created` + `wait_started`) e os
  autotestes. O pedido traz a imagem (caminho
  NT de um arquivo do volume, arquivo do volume ou bytes), o nome curto e
  os parâmetros, e opcionalmente o pai de quem herdar os handles. A ordem:
  abrir a imagem e ler o layout (uma falha não cria
  nada: `CreateFailure::FileOpen`/`ExeFormat`); `create_process` (EPROCESS,
  PID, raiz própria, `ProcessState`, seção de imagem); a herança de handles
  do pai, se pedida; anexado ao processo
  novo, as cópias de sistema, o executável, a pilha, a PEB
  (`mm/peb_teb.rs`, o MmCreatePeb: imagem, ApiSetMap +0x68, NLS, heap,
  versão, subsistema da imagem; PEB.Ldr NULL para a ntdll;
  CriticalSectionTimeout com o MmCriticalSectionTimeout, os segundos do
  `CriticalSectionTimeout` do Session Manager vezes -10.000.000, 30 dias
  por padrão; com mais de uma hora a ntdll espera sem prazo numa seção
  crítica), a PEB_LDR_DATA
  do loader do kernel (`loader::create_kernel_ldr`), os parâmetros
  (`ps/process_parameters.rs`, o RtlCreateProcessParametersEx: bloco
  auto-relativo com ImagePathName, CommandLine, diretório corrente, DLLs,
  título, desktop, shell, runtime, ambiente com EnvironmentSize, console e
  handles padrão), a TEB (`peb_teb::create_teb`, o MmCreateTeb, também
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
  0x58 bytes do 19041, com as vistas por estado), a PS_ATTRIBUTE_LIST copiada
  uma vez (honra ImageName, ParentProcess com PROCESS_CREATE_PROCESS,
  PriorityClass, ProtectionLevel (o processo novo recebe o PS_PROTECTION
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
  as saídas vão para as VAs sondadas: PsCreateSuccess com a PEB e o bloco de
  parâmetros do filho (FileHandle e SectionHandle NULL), ou
  PsCreateFailOnFileOpen/PsCreateFailExeFormat. O KPROCESS é sinalizado no
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
  (`refresh_ready_user_threads` a torna a corrente), e as APCs de kernel
  drenadas também (`drain_kernel_apcs`); os pumps de ALPC, de pacotes de
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
    do `\GLOBAL??`).
  - Até 16 arquivos, cada um com um `_MMPAGING_FILE` do PDB no pool. O
    espaço livre é um bitmap do tamanho máximo; as páginas 0 e 1 ficam
    reservadas.
  - `commit.rs`: commit do sistema. O limite começa nas páginas físicas e
    sobe com o tamanho de cada arquivo. A página privada comitada cobra do
    sistema antes do processo. Acima do limite a alocação falha com
    STATUS_COMMITMENT_LIMIT.
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
    MmUnlockPages.
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
    não cresce nem encolhe.
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
    $Secure com um descritor no $SDS e os índices $SDH/$SII, $UpCase pelo
    RtlUpcaseUnicodeChar, $Extend; 12..15 reservados), $Quota, $ObjId e
    $Reparse depois dos registros de usuário (o NTFS só aceita uma entrada de
    índice que aponte um registro abaixo de 16 na raiz), os índices $I30 nomeados e em B-tree quando não cabem no
    registro, e a cópia do setor de boot no último setor, fora do volume.
    Nas runlists, a contagem de clusters também leva o byte de sinal livre,
    porque o ntfs.sys a lê com sinal: o $Bad do volume de 41796 clusters do
    `nvme.img` (0xA344) vai em três bytes (44 A3 00); em dois seria um run
    de -23740 clusters e o NtfsCheckFileRecord recusaria o $BadClus
    (STATUS_FILE_CORRUPT_ERROR na montagem).
    O leitor do kernel lê o mesmo volume; a listagem dele esconde os
    registros abaixo de 16, como a enumeração do NTFS.
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
  `ps/set_process_information.rs`). Serviços que essa cadeia pede e que
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
  MEM_RELEASE com a faixa da região inteira. O marcador `SMSS_CSRSS_OK` sai
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
  SessionPowerInit (41), SessionPowerCleanup (63) e SystemVideoState (29).
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
  NtIsUILanguageComitted do csrss (`ps/locale.rs`), as classes
  ProcessDefaultHardErrorMode e ProcessHandleCheckingMode do
  NtSet/NtQueryInformationProcess (`ps/set_process_information.rs`,
  `ps/query_process.rs`, com o ProbeForRead do alinhamento de cada classe),
  a ThreadBreakOnTermination do NtSetInformationThread
  (`ps/set_thread_information.rs`) e as classes de tamanho fixo
  SystemFlagsInformation, SystemPhysicalMemoryInformation,
  SystemKernelDebuggerInformation (o KdDebuggerEnabled e o
  KdDebuggerNotPresent, sondagem de alinhamento 1) e
  SystemHypervisorSharedPageInformation do NtQuerySystemInformation
  (`ex/system_information.rs::query_fixed`, também no Zw). O NtCreateTimer,
  o NtSetTimer e o NtCancelTimer de modo usuário são adaptadores do ETIMER
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
  no 19041. Um NtCreateKey com componente intermediário ausente devolve
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
  dele (NtSetInformationThread, classes 2 e 3 como no NT), o csrss assina
  os nomes WNF da instalação (`cm/wnf_defaults.rs`) e o sxssrv.dll lê a
  chave SideBySide (`cm/seed.rs`). Depois o CsrSbApiPortInitialize cria a
  porta LPC `\Windows\SbApiPort` (as portas LPC de modo usuário, no item
  seguinte), o smss mestre se conecta a ela e o SmpSbCreateSession pede ao
  csrss a sessão do wininit.exe: o csrss põe a `\Windows\ApiPort` como
  ProcessExceptionPort do processo novo, lê ThreadTimes e
  ThreadIsTerminated (NtQueryInformationThread) e retoma a thread; a
  ProcessDeviceMap do NtQueryInformationProcess dá as letras do
  `\GLOBAL??` (`ob/device_map.rs`). O wininit.exe conecta à
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
  CreateWindowStationW, o user32 abre o kbdus.dll e o NtUserCreateWindowStation
  manda ao csrss um pedido síncrono de kernel direto à porta de conexão
  `\Windows\ApiPort` (`server::connection_request`). O idioma do convidado
  é o desta instalação (o xtask copia o `Control\Nls\Language`, o
  `Control\MUI\UILanguages` e o perfil de idioma da DEFAULT do Registro
  desta máquina, e põe no volume os `.mui` dos programas nos idiomas de
  interface daqui, ou no idioma de fallback (o `DefaultFallback` do idioma
  e o `InstallLanguageFallback`, como o en-US) para um programa sem `.mui`
  neles; o kernel lê o `Control\Nls\Language` no boot,
  `ps/locale.rs`): os callbacks ao user32 do wininit acham o
  `<idioma>\USER32.dll.mui`. O ConvertHandleAndVerifyLoc do win32kbase
  confere o layout de teclado pelo nome do ObQueryNameString do
  FILE_OBJECT (a QueryNameProcedure do tipo File, `io/file/information.rs`,
  com o FileName do caminho da abertura) contra o `\SystemRoot\System32\`
  e o reabre pelo dispositivo (o alias de System32 do volume de boot vale
  também nessa abertura), e o NtUserCreateWindowStation devolve a WinSta0.
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
  notificação de um arquivo de driver, `io/completion/file_port.rs`). O
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
  do DcomLaunch, e o `Control\Power` copiados desta máquina) e passa pelo
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
  que trata as mensagens no processo System e aceita o primeiro cliente),
  sobe o endpoint `umpo` e pede o NtPowerInformation de modo usuário
  (`po/power_information.rs`: o PlatformInformation, o PlatformRole e o
  PowerInformationInternal 4). As definições WNF desta máquina
  (`Control\Notifications`), a ProductOptions e a ProfileList vêm do
  xtask, e o NtGetCompleteWnfStateSubscription entrega ao modo usuário os
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
  `WinStations` (copiados desta máquina pelo xtask), carrega o sysntfy.dll,
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
  contam. NtImpersonateClientOfPort e NtAlpcImpersonateClientOfPort
  impersonam a thread que mandou a mensagem pendente (SeCreateClientSecurity
  com o QOS da porta do cliente e SeImpersonateClientEx); o
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
  (`ps/mitigation_policy.rs`: código dinâmico, pontos de extensão,
  assinatura e fontes, com as recusas do 19041); a ProcessBasePriority
  (`ps/set_process_information.rs`); o pacote de espera sobre um processo
  (`ps/user/wait_packets.rs`: o pool de threads do wininit espera assim o
  fim do services.exe); e o diretório `\Security` com o evento
  `LSA_AUTHENTICATION_INITIALIZED` do SepInitializationPhase1
  (`se/initialization.rs`), que o lsass.exe abre. Os dados vêm desta máquina
  no build: o contexto de ativação padrão do sistema, que o sxssrv.dll gera
  no primeiro CreateProcessW, precisa das chaves de SideBySide\Winners e dos
  manifestos de WinSxS do Microsoft.Windows.SystemCompatible e das
  dependências obrigatórias dele, e o contexto do LogonUI.exe, do dwm.exe e
  das DLLs da tela de logon com manifesto próprio pede o
  Microsoft.Windows.Common-Controls 6.0 (as chaves, os manifestos e os
  arquivos que eles listam, como o comctl32.dll da versão 6,
  `xtask/src/side_by_side.rs`); o services.exe lê as chaves de serviço da
  cadeia do LSM (DcomLaunch, RpcEptMapper, RpcSs e LSM) e as do PlugPlay e
  do Power, que ele inicia pelo nome antes dos outros, o
  Control\ServiceGroupOrder, os valores EarlyStartServices e
  SvcHostSplitThresholdInKB de Control (o conjunto inicial e a separação
  dos serviços de um svchost) e os grupos do svchost
  (`xtask/src/user_services.rs`). A tela de logon da sessão 1 leva o fecho
  de imports do dwm.exe e do LogonUI.exe com o XAML e os provedores de
  credencial (`LOGON_SCREEN_PROGRAMS` em `xtask/src/windows_binaries.rs`),
  os `.mun` e os `.pri` de `\Windows\SystemResources` desses programas, as
  fontes de `\SystemRoot\Fonts` com o GRE_Initialize, o FontSubstitutes, o
  FontLink e a chave Fonts (`xtask/src/fonts.rs`), e o CLSID do
  LogonUIController com as classes WinRT das DLLs do volume
  (`WindowsRuntime\ActivatableClassId`, `xtask/src/logon_screen.rs`); a
  hive gerada põe uma chave com mais de 1012 subchaves em folhas sob uma
  raiz 'ri' (`xtask/src/hive_image.rs`). A inicialização do LSA (o
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
  (`ps/user/alpc.rs::deferred_send`). O envio só acontece com o bit 0 do
  Flags do bloco, como no 19041: o rpcrt4 deixa no bloco a mensagem do
  envio anterior e liga o bit só quando há resposta nova. Antes, a mensagem
  velha era reenviada a cada espera (STATUS_INVALID_PARAMETER ou
  STATUS_REPLY_MESSAGE_MISMATCH, e uma resposta velha podia chegar a um
  pedido novo com o mesmo MessageId).
- **Os tokens de logon** (`se/token/create.rs`, `se/token/set_information.rs`):
  o NtCreateToken e o NtCreateTokenEx do LSA (SeCreateTokenPrivilege
  habilitado, TokenType, o nível pelo QoS num token de impersonação, a sessão
  de logon criada pelo RmCreateLogonSession, dono e grupo primário entre o
  usuário e os grupos, os grupos obrigatórios habilitados, o rótulo de
  integridade, a origem TOKEN_SOURCE e os atributos de segurança de usuário),
  e o NtSetInformationToken das classes TokenOwner, TokenPrimaryGroup,
  TokenDefaultDacl, TokenSessionId e TokenSecurityAttributes (as operações
  ADD, DELETE, REPLACE e REPLACE_ALL), com a máscara de classes e os acessos
  do 19041. O TokenSessionReference (só o valor 0, com o SeTcbPrivilege) faz
  o token largar a sessão de logon (TOKEN_SESSION_NOT_REFERENCED em
  TokenFlags): o LsapSetSessionToken do lsasrv faz isso com o token de cada
  sessão que guarda, e o RmDeleteLogonSession não conta esse token. O
  TokenIntegrityLevel troca o nível do SID de integridade do token (subir
  pede o SeTcbPrivilege e um token sem uso; abaixo de High e de Medium os
  privilégios fora das máscaras do 19041 ficam desligados, mas presentes):
  o dwminit do winlogon sobe assim o token da conta DWM-n para System. O CreateProcessAsUser passa o token no PS_ATTRIBUTE_TOKEN do
  NtCreateUserProcess: o processo novo recebe uma cópia dele com o SessionId
  da sessão do processo (o SeSubProcessToken do
  PspInitializeProcessSecurity), e quem cria precisa do
  SeAssignPrimaryTokenPrivilege habilitado no token efetivo.
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
  só registra). A
  conexão de volta ainda não leva o PORT_VIEW de 4 KB do NT (o
  ZwSecureConnectPort de kernel não monta vistas), e o SepRmCallLsa (os
  comandos do Reference Monitor ao LSA) ainda não existe. O lado servidor
  LPC de modo kernel são o ZwCreatePort, o ZwReplyWaitReceivePort (a
  recepção legada com o PortContext, `server::begin_kernel_legacy_receive`),
  o ZwAcceptConnectPort (o `server::accept_legacy` em KernelMode) e o
  ZwCompleteConnectPort; o autoteste `test/kernel_waits.rs` põe um servidor e
  um cliente LPC de kernel em threads de sistema.
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
    IoCompletionReserve, NtAllocateReserveObject), com o pacote embutido que
    o ZwSetIoCompletionEx publica (`io/completion/set.rs`) e a retirada
    devolve;
  - NtQuerySystemInformationEx de modo kernel em `ex/system_information.rs`
    (classes 107, 121 e 180, com o KeNodeDistance e o steering de
    interrupções de `ke/`), PsChargeProcessPoolQuota/PsReturnPoolQuota em
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
    condrv (`CONDRV_OK`).
- **Os exports que eram os últimos imports de drivers de software** (76,
  cada um no componente dono, conferidos contra o ntoskrnl 19041):
  - SDDL em `se/sddl.rs` (SeConvertSidToStringSid, SeConvertStringSidToSid
    e SeConvertSecurityDescriptorToStringSecurityDescriptor, com as tabelas
    de apelidos de SID, tipos, flags e direitos de ACE do binário e o
    comprimento reservado que o original devolve) e os níveis de assinatura
    em `se/signing_level.rs`, pelos slots nomeados da tabela de callbacks da
    CI (`se/code_integrity.rs`); sem CI inicializada, FALSE/STATUS_UNSUCCESSFUL;
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
    (`io/file/directory_notify.rs`), NtSetInformationFile, NtFsControlFile e
    ZwCreateSymbolicLinkObject;
  - Ke, Ex, Po, Mm e Io: IoSizeOfIrpEx/IoInitializeIrpEx/IoCleanupIrp,
    IoEnqueueIrp, IoSetIoAttributionIrp e IoReportResourceForDetection; os
    releases Exf de push lock, a espera por endereço sobre push lock
    (ExBlockOnAddressPushLock/ExUnblockOnAddressPushLockEx) e o
    ExEnterCriticalRegionAndAcquireSharedWaitForExclusive;
    ExGetSystemFirmwareTable (`ex/firmware_table.rs`, provedores 'RSMB' e
    'FIRM'); MmAreMdlPagesCached (o CacheAttribute de cada PFN) e
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
  de programas que o luafv.sys lê), `ntos/cm/service/boot_services.rs` e
  `ntos/cm/service/inbox_drivers.rs`, na mesma árvore `cm`/`cm::service`
  de módulos), com que `xtask/src/hive_image.rs` grava os arquivos SYSTEM,
  SOFTWARE, SAM, SECURITY e DEFAULT de `\SystemRoot\System32\config`.
  Esses arquivos de tabela são dados puros: não usam nada do kernel. O
  `kernel/build.rs` inclui `ntos/ke/services.rs` para gerar a ntdll de
  bring-up.
- **Hives do Registro** (`ntos/cm/hive/`, `hive_list.rs`): a arena de
  `cm/registry.rs` é o namespace (o papel dos KCBs com cache completo); um
  nó de uma hive de arquivo guarda a célula 'nk' dele, e cada mudança no nó
  (chave criada ou excluída, valor gravado ou removido) vai na mesma hora,
  sob a mesma trava, para as células da hive (`hive/key_cells.rs`,
  `hive/index.rs`, `hive/security_cells.rs`), marcando os setores de 512
  bytes sujos. O NtFlushKey grava o log incremental (.LOG1/.LOG2
  alternados) e as faixas sujas no primário, entre o bloco base
  invalidado e o validado (`hive/sync.rs`); a carga de um primário
  invalidado aplica os logs (`hive/log.rs`). As chaves voláteis não ganham
  célula. A classe de uma chave (o Class do NtCreateKey, capturado como no
  CmCreateKey: Length ímpar dá STATUS_INVALID_PARAMETER) fica no nó e numa
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
  as tabelas chamam de `CurrentControlSet`), começa a lista de hives
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
  `\REGISTRY\A` só abre relativo a um handle de hive de aplicativo.
- **Escritor preguiçoso** (`cm/lazy_flush.rs`): a hive de arquivo que fica
  suja arma um KTIMER de 60 s (2 s expedito); a DPC enfileira o
  trabalhador no work item do sistema, que descarrega as hives sujas menos
  as REG_NO_LAZY_FLUSH (`hive_list::lazy_flush_pass`, sem esperar uma
  descarga em curso) e rearma se sobrou sujeira. O escritor fica retido 60
  s depois da montagem das hives (o atraso do boot do CmpCmdInit). O
  desligamento ordenado (`po/shutdown.rs`) chama o `lazy_flush::shutdown`,
  o CmShutdownSystem: para o escritor e descarrega todas as hives, depois
  do ShutdownTime que o ExShutdownSystem(0) grava.
- **Hives de aplicativo e restaurações especiais** (`cm/hive_list.rs`):
  REG_APP_HIVE liga a hive em `\REGISTRY\A\{...}`, devolve o handle da
  raiz, reaproveita a hive já carregada do mesmo arquivo e a descarrega no
  fechamento do último handle; REG_LOAD_HIVE_OPEN_HANDLE devolve o handle
  da raiz de uma carga comum e o Event da carga é sinalizado na descarga;
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
  Winlogon sem os do usuário daqui, Setup e PriorityControl) e põe no volume
  os ServiceDll dos outros serviços do grupo DcomLaunch. O autoteste é o
  `test/user_service_chain.rs`.

## 5. Testes

- **Autotestes no QEMU** ficam em `ntos/test/` e rodam conforme
  `--kernel-test-scope`. A suíte completa:
  `cargo xtask test-boot PHASE3_SELFTEST_OK 240000 --kernel-test-scope=all --smp=4 --expect=PHASE4_SELFTEST_OK ... --expect=PHASE6_SELFTEST_OK --expect=MULTIPROCESS_OK --expect=PHASE7_SELFTEST_OK --expect=KBDTEST_OK --expect=SELFTEST_OK`
  (os `--expect` são procurados em ordem, cada um depois do anterior: o
  `MULTIPROCESS_OK` sai dentro da fase 7, antes do `PHASE7_SELFTEST_OK`).
- **Validação inteira**: `cargo xtask test-all` (`xtask/src/test_all/`) roda
  a suíte completa com 4 CPUs e com 1 (`suite-smp4`, `suite-smp1`, prazo de
  900 s) e todo `[[teste]]` de `docs/status/components.toml`, cujo `comando`
  é um `cargo xtask test-boot` completo (o test-all troca só o
  `--build-dir`). Cada execução tem a pasta `build/test-all/<id>` (`<id>.<n>`
  com `--repeat`). As opções de boot dos testes (`--kernel-test-scope`,
  `--start-driver`, `--kd`, `--initial-process`, `--storage`, `--display`,
  `--pnp-root`, `--usb`, `--trace-driver-api`, `--console-mirror`) não entram no
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
  do prazo do test-boot mais o `--hold` e 2 minutos é morta com o QEMU. Cada
  QEMU compromete ao subir toda a memória do convidado (uns 5 GB com
  `-m 4096`), e com o commit do host esgotado processos morrem sem mensagem
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
  `--start-driver` liga o Code Integrity já no fim da fase 1, antes da
  árvore de dispositivos, como no NT: os drivers que o PnP carrega (o
  acpi.sys, o pci.sys, o msisadrv.sys com o KMDF, o i8042prt.sys e os
  filtros de classe) passam pela validação
  (`CI_KERNEL_IMAGE_RESULT name=\FS\i8042prt.sys status=0x0`). Os testes
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
  (`BEEP_DEVICE_OK`), e os reconhecedores do fs_rec.sys respondem a um
  IRP_MN_MOUNT_VOLUME sobre o volume NTFS (`FS_REC_OK`).
- **Depurador do kernel, cliente** (`tools/kd-client`): só a biblioteca
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
  - Símbolos (`symbols.rs`, `pe.rs`, `pdb.rs`): o `kernel.elf` com os nomes
    do Rust legíveis; para cada binário da Microsoft carregado, os exports
    do PE desta máquina e os nomes públicos do PDB público dele. O PDB vem
    do cache `build/symbols` (`OPENNT_SYMBOLS` troca a pasta) ou do servidor
    público de símbolos, baixado pelo `curl` numa thread
    (`OPENNT_SYMBOL_DOWNLOAD=0` desliga). O download é o mesmo do
    `cargo xtask nt-types`. Os módulos aparecem sem extensão
    (`ntfs!NtfsCommonCreate+0x1a3`); `nt` é o kernel.
  - Pilha (`unwind.rs`): o contexto (RIP, RSP e os registradores
    conhecidos) passa de quadro em quadro. Nos binários da Microsoft, o
    desenrolar virtual do x64 pela `.pdata` e pelo UNWIND_INFO (push,
    alocação, registrador de quadro, registradores salvos, quadro de
    máquina, informação encadeada; epílogo reconhecido no quadro de cima;
    função folha). A tabela vem do arquivo desta máquina ou da memória do
    alvo. No código do OpenNT, os frame pointers (e o prólogo no quadro de
    cima). Um driver chamado pelo kernel e o kernel chamado pelo driver
    desenrolam um sobre o outro. O `gu` sai pelo quadro de cima do mesmo
    desenrolar.
  - Tipos (`tpi.rs`, `types.rs`): o TPI do `build/symbols/ntkrnlmp.pdb` (o
    mesmo leitor do `cargo xtask nt-types`, que agora o usa daqui).
    `dt _IRP endereço` mostra a struct campo a campo; enums com o nome do
    valor, bitfields, arrays de caracteres como texto, ponteiros com o
    símbolo. O PDB carrega na primeira expressão tipada.
  - Expressões (`expr.rs`): números (`0x`, `` ` ``, `0n`, hexadecimal sem
    prefixo), registradores (`@rax`, `%rax`, `rax`), `$variáveis`,
    símbolos do Rust e `módulo!símbolo`, `poi`/`by`/`wo`/`dwo`/`qwo`,
    `[x]`, `$iment(módulo)`, `sizeof(tipo)`, os operadores do C e os acessos
    tipados (`((_IRP*)@rcx)->Tail.Overlay.CurrentStackLocation`, `*p`,
    `&s.Campo`, `p[2]`).
  - Breakpoints (`client.rs`): software, hardware de execução, escrita e
    acesso (`ba e1|w4|r8`), condição (`bp x 3 /w "@rax == 7"`: a partir do
    terceiro acerto, só com a condição verdadeira; os outros acertos seguem
    sozinhos), adiados (`bu`: o símbolo de um módulo que ainda vai carregar)
    e parada por carga de módulo (`sxe ld:ntfs.sys`). Os dois últimos usam
    um breakpoint interno na notificação de carga de imagem do kernel
    (`ps::notify::image::notify`): o cliente relê a lista de módulos, arma
    os adiados e segue sozinho quando o módulo novo não é o pedido.
    `.bpsave`/`.bpload` gravam e recriam a lista.
  - Processos de usuário (`user.rs`, `client.rs`): `.process` escolhe o
    processo e o cliente o reaplica a cada parada; numa parada do anel 3, o
    processo dela vira o das leituras. Os módulos de usuário (a PEB.Ldr e as
    imagens do VAD) entram nos símbolos à parte (`set_user_modules`), com os
    exports do PE desta máquina e o PDB público. A pilha de uma thread de
    usuário sai do CONTEXT salvo dela. Comandos: `.process`, `lmu`,
    `handles`, `vad`, `uthreads`, `ustack`, `kmap`, `events`, `uex`.
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
  - Testes (`cargo test -p kd-client`): pacotes, resposta de parada,
    registradores, PE e `.pdata`, UNWIND_INFO e o desenrolar misto sobre uma
    pilha montada, públicos de PDB, tipos sobre um TPI montado, expressões,
    bugcheck, o formato do rastro, a árvore de chamadas e a comparação. Contra
    um alvo de mentira num socket local (`tests/fake_target.rs`, o stub em
    `tests/support/fake_stub.rs`, também usado pelos testes do `kd-mcp`): a
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
    antes.
- **Depurador gráfico** (`tools/kd-gui`, binário `opennt-dbg`).
  - Uso: `cargo run -p kd-gui --release -- --launch` roda o mesmo build e
    QEMU do `cargo xtask debug --launch` e abre a janela; `--connect=HOST:PORTA`
    entra num QEMU aberto.
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
    tira o breakpoint na linha escolhida, Ctrl+B para. Barra de estado:
    conexão, estado do alvo, CPU, thread, processo e IRQL. Tema escuro e
    claro.
  - Painéis: Desmontagem (iced-x86, sintaxe MASM, marcador do RIP, margem
    de breakpoints, destinos dos desvios); Código-fonte (a linha do DWARF);
    Registradores (os que mudaram em vermelho, editáveis); Observação
    (expressões com valor e tipo; um valor tipado abre a struct campo a
    campo, e campos de struct e ponteiros abrem de novo); Variáveis locais
    (parâmetros e variáveis do quadro de cima pelo DWARF do `kernel.elf`:
    frame base, registradores e listas de posições, pelo `gimli`; o
    `cargo xtask debug`, que o depurador roda, compila o perfil `depuracao`,
    com o DWARF completo; os builds comuns levam só as tabelas de linha, que
    bastam para o arquivo:linha e os nomes de função, mas não para as
    variáveis); Memória
    (bytes, words, dwords, qwords, ASCII, UTF-16; procura de bytes, texto ou
    UTF-16; clique duplo num qword segue o ponteiro); Pilha de chamadas (RSP
    de cada quadro e o método do desenrolar); Breakpoints (condição,
    contagem, acertos, adiados, carga de módulo); Módulos (PDB baixado ou
    não; clique abre o `lmv`); Objetos do NT (as consultas do `kd/inspect.rs`,
    o módulo e qualquer struct do PDB; endereços azuis abrem como IRP,
    dispositivo, driver, thread ou processo pelo botão direito); Análise do
    bugcheck (abre sozinha numa parada pelo KeBugCheckEx); Rastro; Comandos
    (histórico e Tab para completar comandos, símbolos e tipos); DbgPrint e
    o log da COM1.
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
  - Teste de fumaça (`cargo test -p kd-gui --release -- --ignored`,
    `tests/smoke.rs`), sem janela: abre o OpenNT com o QEMU sem tela, anexa
    no começo do boot, para na carga do ACPI.sys real (`sxe ld`), para
    dentro dele no retorno de uma chamada ao IoCreateDevice e confere a
    pilha pela `.pdata` com os nomes do PDB público, rastreia 200 instruções
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
- **Depurador de engenharia reversa** (`tools/kd-re`, binário `opennt-re`).
  - Uso: `cargo run -p kd-re --release -- --launch` (com
    `--initial-process=smss` o csrss.exe real roda); `--connect=HOST:PORTA`;
    `--script=ARQ` roda um roteiro depois do attach.
  - Layout no estilo dos depuradores de engenharia reversa: abas no alto
    (CPU, Grafo, Log, Notas, Breakpoints, Mapa de memória, Pilha de
    chamadas, SEH, Script, Símbolos, Código-fonte, Referências, Threads,
    Handles, Rastro, Strings, Patches, Comentários/Rótulos, Processos,
    Observação, Objetos do NT, Bugcheck), barra de comando e barra de estado
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
  - Análise automática (`kd_mcp::annotate`, a mesma da ferramenta
    `disassemble` do servidor MCP): os colchetes das funções na margem
    (`.pdata`, símbolo com tamanho ou o fluxo de código) e dos laços (até
    três níveis), do cache por função; os comentários automáticos das
    chamadas a APIs conhecidas, com os argumentos pelo preparo antes do
    `call` ou, na linha do RIP, pelos registradores e pela pilha de
    verdade; o nome vem do destino ou da entrada da IAT (`__imp_`); as
    strings referenciadas por operandos relativos ao RIP.
  - Referências cruzadas (X ou Ctrl+R): o índice do módulo
    (`refs::xref_index` sobre a imagem), feito na primeira vez e guardado
    até um patch; a janela lista origem, local, tipo e instrução.
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
    (`Request::Mcp`); o `kd_mcp::Server` roda com a sessão da janela como
    `Engine`, e a janela relê a parada depois de cada ferramenta.
  - Backend (`backend.rs`, `backend/views.rs`): além do snapshot do
    `opennt-dbg`, monta o processo escolhido, os Dumps, a pilha, a caixa de
    informação, os argumentos dos quadros (o espaço de home e os primeiros
    da pilha), os tratadores de exceção (UNWIND_INFO, com a tabela do
    `__C_specific_handler`), o grafo, as buscas, o mapa de memória, os
    handles, as threads de usuário, os símbolos e imports de um módulo, os
    patches e os roteiros.
  - Imagens para as buscas (`kd_client::image`, reexportado em `scan.rs`): o PE desta máquina (cabeçalhos e
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
  - Teste de fumaça (`cargo test -p kd-re --release -- --ignored`,
    `tests/smoke.rs`), sem janela, com `--initial-process=smss --smp=1`: para
    na carga do basesrv.dll no csrss.exe real (o evento de imagem), confere
    o contexto (PEB, módulos da PEB.Ldr com os símbolos da ntdll), para num
    breakpoint de usuário no ntdll!LdrLoadDll com a pilha até o CSRSRV, lê
    threads de usuário, handles e o mapa de memória, monta o grafo de uma
    função do kernel e de uma da ntdll, acha referências conhecidas no
    ACPI.sys real (`PNP0A03` em ASCII e uma UTF-16) e no CSRSRV.dll, roda um
    roteiro e desenha a janela fora da tela.
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
  - Preferências e banco por módulo (`preferences.rs`): fontes, escala,
    cores que trocam as da paleta, o editor de atalhos (as ações com a
    tecla, conflitos em vermelho) e as paradas em eventos (mandadas ao
    alvo na primeira parada e quando mudam), em
    `%APPDATA%/opennt-re/preferencias.json`. O banco por módulo
    (`<build>/opennt-re/db/<modulo>.json`) guarda comentários, rótulos,
    marcadores e breakpoints por RVA; é lido na abertura e gravado quando
    muda, e os breakpoints guardados são armados quando o módulo aparece.
  - Testes de unidade (`cargo test -p kd-re --release`): o destaque, os
    formatos do Dump, o modelo do editor de breakpoints, as colunas dos
    operandos, os formatos dos XMM e as preferências e o banco por módulo
    (ida e volta pelo disco).
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
- **Servidor MCP** (`tools/kd-mcp`, binário `opennt-mcp`).
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
    JSON em `content`.
  - Recursos: `opennt://serial-log`, `opennt://dbgprint`,
    `opennt://breakpoints` e `opennt://modules`.
  - Sessão (`engine.rs`): o trait `Engine` dá o cliente, o `launch`
    (`kd_client::launcher`), o `connect`, o log da COM1, o monitor do QEMU e
    o cache das imagens com os índices de referências cruzadas.
    `Standalone` é o do binário; a janela do opennt-re implementa o mesmo
    trait.
  - `screenshot` (`screenshot.rs`): `screendump` do monitor HMP do QEMU
    aberto pelo `launch`, em PNG; sem PNG no QEMU, PPM convertido para PNG
    no crate.
  - Testes (`cargo test -p kd-mcp`): o protocolo (negociação, a lista de
    ferramentas com esquemas válidos, os erros, lotes), as ferramentas
    contra o alvo de mentira do `kd-client` (registradores estendidos,
    memória, desmontagem com o comentário da chamada ao IoCreateDevice,
    breakpoint de uma vez só, parada, pilha, símbolos, recursos, as
    ferramentas novas: o monitor com a chamada ao IoCreateDevice, o IRP de
    CREATE, o Registro, o namespace, os arquivos e os erros sem
    reprodução e sem monitor do QEMU) e o
    binário em stdio. Ponta a ponta (`cargo test -p kd-mcp --release --
    --ignored`, `tests/e2e.rs`): o binário em stdio abre o OpenNT pelo
    `launch`, para, lê os registradores, arma um breakpoint em
    `kernel::ntos::ke::run_kernel_tasks`, continua até ele, confere a
    desmontagem e a pilha, tira o breakpoint, continua e espera
    `[shell] pronto` na COM1 (`OPENNT_MCP_BUILD_DIR` troca o build).
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
  os de falha são `*** PANIC`, `*** EXCECAO`, `SELFTEST FALHOU` e `*** STOP`
  (a parada do KeBugCheckEx; com `--expect-stop` o STOP faz parte do teste,
  como no `bugcheck`). O `test-boot` procura falhas desde o boot até
  a última saída esperada e, com `--hold=MS`, por mais MS milissegundos. No
  `--keys`, `{combo}` vai cru ao `sendkey` do monitor (teclas pressionadas
  em ordem e soltas ao contrário, como `{ctrl_r-scroll_lock-scroll_lock}`).

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
resultado nos textos do PNG; o `cargo xtask status` os lê de lá.

O `test-boot --watch-screen` lê a tela durante o teste, pelo mesmo QMP, a
cada 2 s (`qemu::watch_screen`). Uma tela gráfica de pelo menos 800x600 com
64 pixels ou mais fora do preto, que não seja o fundo azul da tela de
bugcheck, põe no log da serial uma linha `[xtask] tela:` (quantos pixels, a
caixa que os contém e as cores mais comuns) e o marcador `FIRST_PIXEL_OK`, e
grava a tela em `<build>/primeira-tela.png`. A tela de texto da VGA (720x400)
e o aviso do QEMU antes da VGA iniciar (640x480) não contam. O vídeo de boot
do OpenNT (o modo VBE 1024x768) é todo preto, e o kernel só desenha nele a
tela de bugcheck: o que aparece ali vem de quem desenha depois do boot.

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
  ObInsertObject. A avaliação não interpreta ACEs condicionais (callback) nem
  listas de tipos de objeto, não audita e não monta o PRIVILEGE_SET dos
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
