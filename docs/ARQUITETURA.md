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
| `tools/kd-client` | o cliente do depurador do kernel, só com a biblioteca padrão: protocolo remoto do GDB, símbolos (`kernel.elf`, exports dos PEs, públicos de PDB), pilha pelos frame pointers, passo por cima e para fora, breakpoints e os comandos de texto; usado pelo `xtask` e pelo `kd-gui` |
| `tools/kd-gui` | `opennt-dbg`, o depurador gráfico (egui/eframe, painéis do `egui_dock`, desmontagem do iced-x86, linhas do DWARF pelo `addr2line`); as dependências dele não entram no build do kernel nem do `xtask` |

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
│   ├── se/            segurança: descritores, ACLs, SIDs, integridade de código
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
│   │   ├── key/       chaves e serviços Nt/Zw de chave
│   │   └── service/   serviços e drivers (base, canal, RPC)
│   ├── rtl/           a Rtl do NT: strings, Unicode, páginas de código, AVL, árvore
│   │   │              rubro-negra (rb_tree), bitmap, exceções, imagens PE, tabelas de
│   │   │              átomos (atom), heap (heap), CRT (crt, printf, scanf)
│   │   └── resource/  recursos de imagens (ldrrsrc) e tabelas de mensagens
│   ├── alpc/          ALPC (connect/, message/, resource/)
│   ├── kd/            depurador do kernel: o estado que os drivers veem e o
│   │                  próprio depurador do OpenNT (protocolo remoto do GDB)
│   ├── po/ etw/ dbgk/ fsrtl/
│   ├── bgk/           console do vídeo de boot (Bgk*)
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
| 0xFFFFA000_00000000 | 320 | pool executivo, dump, memória contígua e independente, visões de sistema, VirtualAlloc de kernel, VAs globais das sessões (0xFFFFA006_80000000), pilhas de kernel das threads (0xFFFFA007_00000000..0xFFFFA008_00000000) |
| 0xFFFFB000_00000000 | 352 | **mapa direto**: toda a faixa física [0, 4 GB) em `DIRECT_MAP_BASE + PA` |
| 0xFFFFC000_C0000000 | 384 | **janela do heap**: heap do kernel (kmalloc, o alocador do Rust) e a arena dos convidados (IRPs, DEVICE_OBJECTs, MDLs, ExAllocatePool2...) sobre os frames de 32 MB a 96 MB |
| 0xFFFFF780_00000000 | 495 | KUSER_SHARED_DATA (visão do kernel) |
| 0xFFFFF800_00000000 | 496 | KPCR, pool de dados, a **imagem do kernel** (0xFFFFF800_40000000), a pilha de boot (topo em 0xFFFFF800_41200000) e a janela de imagens de kernel (0xFFFFF801_00000000..0xFFFFF802_00000000) |
| 0xFFFFF900_00000000 | 498 | **espaço de sessão**: tabela de topo própria de cada sessão (vazio na raiz do System e dos processos sem sessão); SessionCore, VA dinâmica (pool de sessão) e imagens de sessão |

**Imagem do kernel.** O ntoskrnl é ligado na sua VA de sistema, como no NT:
a ImageBase do PE é `KERNEL_VIRTUAL_BASE` = 0xFFFFF800_40000000 (cabeçalhos
na primeira página, `.text` em +0x1000), e é essa base que a lista de módulos
carregados, o KDDEBUGGER_DATA64 e o `RtlPcToFileHeader` veem. O stage2 lê o
arquivo do disco para os frames a partir de 1 MB (offsets do arquivo == RVAs),
confere o cabeçalho (ImageBase, SizeOfImage, entrada) e mapeia exatamente
SizeOfImage páginas de 4 KB de supervisor, RW e executáveis na ImageBase, com
tabelas fixas em 0x83000-0x8CFFF (PDPT, PD e oito PTs). A pilha de boot é
outra VA de sistema na mesma PD: 383 páginas RW e NX terminando em
`BOOT_STACK_TOP`, sobre os frames logo abaixo de 18 MB (a imagem pode ir até
15,5 MB, nos frames de 1 MB a 16,5 MB), com uma página de
guarda sem mapeamento embaixo (PT em 0x8D000). O stage2 carrega o GDTR pela VA
do mapa direto e entra no kernel com RSP = BOOT_STACK_TOP - 8.

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
encadeado do ntoskrnl (`interrupt_object::dispatch_chain`). Uma thread que
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
diferença.

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
thread volta direto à fila). Quem apronta é o sinal (o KiWaitTest,
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
(`wait::wake`), que sonda a operação de novo. As demais esperas genéricas de
uma condição sem objeto a sinalizar (`context_switch::wait_until`, como a
remoção de um callback à espera do fim das chamadas em curso) tiram a thread
das prontas com a condição sondada pelo despachante a cada tick
(`scheduler::block_polled`). As listas e os registros das esperas ficam sob o
lock do despachante (`wait::lock`), o mesmo do estado das filas. O
contexto de boot, que é o próprio despachante da CPU, espera girando o
`pump_kernel` (interrupções de dispositivo abaixo de DISPATCH_LEVEL, timers,
DPCs, work items e o tick, que entra nas threads de kernel). O autoteste
`ntos/test/kernel_waits.rs` (fase 6) roda duas threads de sistema em
pingue-pongue por dois eventos e por duas KQUEUE (a parada tem o bloco na
WaitListHead, fica Waiting e não gasta ciclo nem troca de contexto enquanto o
sistema gira; o sinal a apronta na hora; o KeInsertQueue entrega a entrada
direto, com a lista vazia e a vaga ocupada), um servidor e um cliente ALPC
de kernel em threads de sistema e um processo de kernel em execução dado como
pronto, que segue fora da fila e espera um prazo sem gastar CPU: pela
contabilidade da própria thread, o KTHREAD.CycleTime não muda em nenhuma das
amostras tiradas enquanto ela está Waiting e ela é despachada uma única vez
(a que a acorda), o que a carga do hospedeiro não altera.

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
PENDING + espera sondada, sem pilha suspensa. O autoteste
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
ALPC, `device_io`, fábricas, timers e pacotes de espera, retoma as threads
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
KTRAP_FRAME) e troca a KTHREAD para a pilha nova. O intervalo do callback é
aninhado no serviço: `usermode::exec_user_callback` guarda o estado por CPU
do serviço de fora (o quadro do despachante, o CONTEXT e o quadro da
syscall, RspBase/RSP0, GS e IF) e entra num CONTEXT próprio em
ntdll!KiUserCallbackDispatcher (o KeUserCallbackDispatcher, publicado quando a
DLL de sistema é mapeada), com os registradores do KiCallUserMode; as
syscalls do callback caem na pilha nova, abaixo dos quadros do serviço de
fora. `threads::run_callback` despacha esses intervalos até o
NtCallbackReturn, que acha o quadro do callout pelo KERNEL_STACK_CONTROL da
InitialStack corrente e grava a saída e o status: syscalls e timer seguem, a
espera PENDING de um serviço aninhado é sondada no lugar (dentro de um
callback a thread não bloqueia: `can_block` recusa com aninhamento), APCs e
exceções são entregues no CONTEXT do callback e uma thread terminada encerra
o laço. Na volta, a KTHREAD retoma a pilha anterior e a do callback volta ao
Mm. O autoteste `ntos/test/multiprocess/user_callback.rs` roda callbacks
simples, aninhados, a volta pelo NtCallbackReturn do KiUserCallbackDispatcher
real, a entrada que não cabe na pilha e o NtCallbackReturn fora de um
callback.

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
  raiz carregada (a vista de imagem anexa ao processo alvo), e desfaz na
  mesma raiz. A imagem principal é do processo (`ProcessState`) e é desfeita
  no término dele.
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
  salvo devolve, então o aninhamento é o dos KAPC_STATE, como no NT. A
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
  IoInvalidateDeviceRelations de um nó da árvore enfileira a reenumeração.
- `install.rs`: as linhas de modelo dos INFs da caixa que atendem o
  hardware emulado (mshdc.inf, disk.inf, volume.inf, volmgr.inf, o
  display.inf com o BasicDisplay.sys para PCI\CC_0300 e o machine.inf com
  o msisadrv.sys para PCI\CC_0601), com o serviço, a classe, os AddReg e
  o ExcludeID de cada seção. O posto segue o instalador (HardwareIDs antes
  de CompatibleIDs): PCI\VEN_8086&DEV_7010 instala o intelide.sys antes do
  pciide.sys de PCI\CC_0101. O ServiceBinary de um driver do repositório
  de drivers (`%13%`, como o BasicDisplay.sys) vai inteiro para o
  ImagePath (`\SystemRoot\System32\DriverStore\FileRepository\...`),
  que o carregador resolve sob o `\Windows` do volume do kernel
  (`\Device\KernelVolume1\Windows`, o destino de `\SystemRoot`).
- `resources.rs`: as listas do NT, os árbitros (primeira opção livre,
  alternativas, compartilhamento) e o tradutor da HAL (IRQ de linha `n` →
  vetor `0x20 + n`, IRQL `n`).
- `root.rs`: o barramento raiz; o barramento PCI interno
  (`drivers/bus/pci.rs`, PCI_HAL\PNP0A03\0) é filho dele. Um
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
- `cm_notify.rs`: o `\CMNotify` (PiUEventDispatch), que abre e fecha; os
  IOCTLs de registro de notificações ainda não têm suporte.

Os PDOs do barramento PCI respondem como o pci.sys (`drivers/bus/pci_pnp.rs`
e `pci_interface.rs`): ids, capacidades, requisitos dos BARs (sem os do canal
IDE legado; um BAR pré-buscável com CM_RESOURCE_MEMORY_PREFETCHABLE),
BUS_INTERFACE_STANDARD e PCI_BUS_INTERFACE_STANDARD,
READ/WRITE_CONFIG. As rotinas que um driver recebe por ponteiro (interfaces
de barramento, DMA_OPERATIONS) são stubs nativos de `hal/amd64/
routine_stubs.rs` (ids privados 0x80000400+). O adaptador de DMA é o da HAL
(`hal/dma.rs`, o HalGetAdapterV2 com a tabela V2 de operações), alcançado pelo
IoGetDmaAdapter através da interface do barramento. IoGetDeviceProperty,
IoOpenDeviceRegistryKey, IoRegisterDeviceInterface (links
`\??\<instância>#{guid}`) e o IoConnectInterruptEx LINE_BASED leem o
devnode.

A árvore sobe no fim da fase 1 com `--storage=real` ou `--display=basic`.
`drivers/bus/device_tree.rs` prepara a raiz com o barramento PCI interno e
deixa com nó do kernel (sem instalação nem AddDevice, como um dispositivo
com driver de boot) as funções que um driver interno já serve naquele
boot: a controladora IDE sem `--storage=real` (o driver ATA interno serve o
volume do boot) e o adaptador VGA sem `--display=basic` (o console em modo
texto). As demais funções seguem o caminho comum; a ponte PCI-ISA recebe o
msisadrv.sys, um driver KMDF, e passa pelo AddDevice e pelo START do
framework.

Com `--storage=real` (`drivers/storage/storage_stack.rs`) sobe a pilha IDE
real: intelide.sys/pciidex.sys na controladora, atapi.sys/ataport.sys nos
canais, disk.sys/classpnp.sys nos discos.

Com `--display=basic` (`drivers/video/display_stack.rs`) o adaptador VGA
recebe o BasicDisplay.sys real. O DriverEntry dele carrega o dxgkrnl.sys
real (ZwLoadDriver do DXGKrnl) e se registra nele (DxgkInitialize); o
AddDevice e o START_DEVICE vão ao dxgkrnl (DpiAddDevice, com o
DxgkDdiAddDevice do miniport, e DpiFdoHandleStartDevice). O dxgkrnl deixa o
início do adaptador (DpiFdoStartAdapterThread, com o DxgkDdiStartDevice)
para a criação da primeira sessão, que o win32k.sys anuncia
(watchdog!SMgrNotifySessionChange no NtUserInitialize).

Com `--pnp-root=acpi` (`drivers/bus/acpi_stack.rs`) a raiz da árvore é a
de um PC ACPI do Windows, no lugar do barramento PCI interno:

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
  (a GSIV 9 da FADT, entregue pelo 8259 no vetor 0x29).
- **Destinos de interrupção** (`hal/interrupt_targets.rs`): HalGetProcessorIdByNtNumber,
  HalGetInterruptTargetInformation (modo físico), HalGetMessageRoutingInfo,
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
O barramento PCI
interno do kernel fica fora dessa árvore; as funções dos drivers internos
são reconhecidas pelos ids de classe do pci.sys (`device_tree.rs`). Os
filhos do pci.sys ainda passam pelo árbitro plano do PnP manager, e não
pelos árbitros dos drivers de barramento; esse árbitro aloca as portas,
a memória e os números de barramento de um nó dentro das janelas do
barramento acima dele (o PCI com o `_CRS`), e as janelas do pai não
colidem com os filhos (`io/pnp/resources.rs`).

Sem as opções nada disso roda.

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
  MmMapLockedPagesSpecifyCache (MDL_MAPPED_TO_SYSTEM_VA). Os pedidos com
  DO_DIRECT_IO do I/O Manager fazem IoAllocateMdl + MmProbeAndLockPages.
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
  da tabela de handles. O heap segue os dois caminhos de criação do
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
- **Trava e energia do KD** (`kd/power.rs`): KdDebuggerLock em
  DISPATCH_LEVEL, a lista dos tratadores de energia do transporte e, com o
  KdPitchDebugger de um boot sem depurador, KdPowerTransitionEx sem efeito
  e KdDisableDebugger com STATUS_DEBUGGER_INACTIVE; com o depurador do
  OpenNT, a transição do ntoskrnl (bit 30 força, D0 reprograma a UART,
  D1-D3 sem efeito, outro estado recusado). DbgCommandString é o serviço 5
  do `int 0x2D` num corpo nativo.
- **Depurador do kernel** (`kd/`): código do próprio OpenNT, ligado por
  `--kd=com2` (`com3`, `com4`; a COM1 é o log). Sem a opção, o boot é o de
  um Windows sem /DEBUG (KdPitchDebugger). Com ela, a fase 0 programa a
  UART (`kd/transport.rs`, E/S programada sem IRQ, FIFO intocada para não
  perder um pedido que chegou antes) e o estado que os drivers veem fica
  como o do KdInitSystem com transporte (`kd/debugger.rs`):
  KdDebuggerEnabled e o bit 0 do KUSER_SHARED_DATA.KdDebuggerEnabled
  ligados, KdComPortInUse com a porta do transporte (como o transporte
  serial do NT a grava), KdDebuggerNotPresent TRUE até um host trocar
  pacotes (então
  FALSE, com o bit 1), e KdDisableDebugger/KdEnableDebugger/KdChangeOption/
  KdRefreshDebuggerNotPresent com a lógica do ntoskrnl (KdDisableCount,
  KdPreviouslyEnabled, KdBlockEnable, a recusa do desligamento com
  KernelDr7 habilitado). O host fala o protocolo remoto do GDB
  (`kd/packet.rs`, `kd/session.rs`): cada processador é uma thread do
  protocolo; `g`/`G`/`p`/`P` sobre o quadro do trap (`kd/registers.rs`, a
  ordem do GDB para x86-64, x87/SSE da área FXSAVE64 da entrada); `m`/`M`/
  `X` andam nas tabelas de páginas do CR3 do processador pelo mapa direto,
  sem travas nem faltas (`kd/memory.rs`); `Z0` grava o 0xCC pelo quadro
  físico, `Z1`/`Z2`/`Z4` são DR0-DR3 (`kd/breakpoints.rs`, publicados em
  KPRCB.ProcessorState.SpecialRegisters); `qRcmd` (o `monitor`) traz as
  consultas do OpenNT (`kd/monitor.rs`: processos e threads pelas listas
  nativas, os registradores de uma thread fora da CPU pelo quadro de troca
  que KTHREAD.KernelStack aponta, módulos, processadores com IRQL e thread
  corrente, objeto por nome, o anel do DbgPrint, breakpoints, bugcheck);
  `qXfer:libraries:read`
  dá a lista de módulos ao GDB. As paradas (`kd/stop.rs`) vêm dos
  trampolins (`hal/amd64/irqstubs.rs`): `int 3` e #DB do anel 0 vão ao
  depurador antes do SEH (o KiDebugRoutine), o tique do relógio no anel 0
  consulta o LSR (o 0x03 do host, ou o começo de um pacote, para a máquina,
  como o KdPollBreakIn), a exceção sem tratador e o KeBugCheckEx param antes
  do diagnóstico e da tela de STOP, e o pânico antes de travar. O dono da
  parada congela os outros processadores com NMI pelo código de IPI do Ke
  (`smp::send_nmi_to_application_processors`; a NMI dos APs prende o
  processador em `rs_kd_freeze_processor` com o quadro publicado) e só os
  degela ao continuar; o passo roda só no dono, com o IF mascarado durante
  a instrução (o original volta depois, e um `pushfq` passo a passo grava o
  IF original), e continuar de um breakpoint dá antes um passo com o byte
  original. Nada da parada aloca nem toma trava: as consultas que usam
  estruturas do Rust (módulos, objeto por nome) só rodam quando nenhum
  processador parado tinha SpinLock ou SharedLock. O DbgPrint vai ao host
  como pacote `O` com a máquina rodando (`kd/print_log.rs`). Os APs ainda
  usam a própria IDT de três vetores: só o BSP trata `int 3`/#DB, e os
  comparadores de hardware são carregados só no dono da parada.
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
  versão, subsistema da imagem; PEB.Ldr NULL para a ntdll), a PEB_LDR_DATA
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
    direta de um dispositivo (sem nome restante) não monta.
  - O volume que os file systems reais montam é o segundo disco IDE,
    exposto pelo driver ATA do kernel como `\Device\AtaVolume1` (DEVICE_OBJECT
    nativo respondido pelo próprio kernel, com VPB, DO_DIRECT_IO, geometria
    do IDENTIFY DEVICE e os IOCTLs de disco, armazenamento e mount manager
    da montagem; o DRIVER_OBJECT `\Driver\AtaVolume` tem a mesma rotina em
    cada IRP_MJ_*, porque um file system pode chamar o MajorFunction do
    dispositivo alvo sem o IofCallDriver). O leitor NTFS do kernel continua dono do disco como D:,
    então as escritas do file system ficam numa sobreposição em memória por
    página de 4 KB, que as leituras do volume aplicam; o disco não muda.
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
- **Itens de trabalho como worker threads** (`io/work_items.rs`): a fila
  do ExQueueWorkItem/IoQueueWorkItem é drenada nos pumps de PASSIVE_LEVEL
  de quem espera, com duas regras das worker threads do NT: um item não
  começa enquanto outro roda na mesma CPU (uma worker que espera não roda
  outros itens) e uma drenagem só roda os itens que já estavam na fila
  quando ela começou. Assim quem espera pelo fim de um item (o FltMgr pela
  montagem postada à FSP do NTFS) confere a espera antes de rodar os itens
  enfileirados por ele — um deles pode esperar pelo que essa thread retém
  (o DeviceLock da montagem em curso). Teste:
  `work_items_one_worker_per_item` na fase 6. Como o
  ExpWorkerThreadBalanceManager, quando a worker desta CPU está bloqueada
  numa espera dentro de um item, o item comum que já espera há 1 s ganha
  uma worker dinâmica (uma thread de sistema que o executa e termina):
  o acpi.sys repassa o START da ponte PCI-ISA ao pci.sys numa worker e
  espera o work item que o pci.sys enfileira. Teste: `stalled_worker`
  (`test/platform_support.rs`).
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
    NtFsControlFile (o IopXxxControlFile com IRP_MN_USER_FS_REQUEST,
    METHOD_BUFFERED e METHOD_NEITHER, acesso do código conferido) e
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
  (`ps/user/csr.rs`), o `\KnownDlls` montado pelo kernel, o provisionamento
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
  chama o NtUserInitialize. A sessão do dxgkrnl
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
  porta LPC `\Windows\SbApiPort` pelo NtCreatePort, que o OpenNT ainda
  não tem (as portas LPC de servidor em modo usuário:
  NtCreatePort/NtReplyWaitReceivePort/NtAcceptConnectPort/
  NtCompleteConnectPort sobre o ALPC), e o csrss termina com
  STATUS_NOT_IMPLEMENTED; o smss da sessão não chega ao wininit.exe, que o
  build já põe no volume com o services.exe e o lsass.exe. O marcador
  `WINSTA0_OK` (`initial_process::desktop_opened`) sai quando o wininit.exe
  tem as Desktops Winlogon e Default da WinSta0, abertas pela ParseProcedure
  da WindowStation.
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
    rotinas privadas (`init/exports.rs::private_routines`);
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
    e ZwSecureConnectPort, sem as vistas de seção do LPC);
  - a abertura de kernel de um nome dentro de um dispositivo sem volume e a
    abertura relativa a um handle de arquivo de dispositivo
    (`io/file/zw.rs`, `io/io_manager.rs::open_related_device_file`), com a
    thread que abre no IRP_MJ_CREATE e a espera de um CREATE pendente, como
    o IopParseDevice. O `--start-driver=condrv` carrega o condrv.sys real e
    `ntos/test/console_driver.rs` abre o servidor, a referência e a conexão
    de um console e troca as mensagens CONNECT e DISCONNECT pelos IOCTLs do
    condrv (`CONDRV_OK`).
- O `xtask` lê fontes do kernel por `#[path]`:
  `ntos/mm/kernel_data_layout.rs` (`.kdata`/`.edata` do PE e páginas de status),
  `ntos/init/export_names.rs` e `ntos/init/native_export_layout.rs` (a EAT do
  PE) e as tabelas das hives de máquina (`ntos/cm/seed.rs`,
  `ntos/cm/session_manager.rs`, `ntos/cm/ini_file_mapping.rs`,
  `ntos/cm/crypto_defaults.rs`, `ntos/cm/service/boot_services.rs` e
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
  célula.
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
  o CmShutdownSystem: para o escritor e descarrega todas as hives.
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
  `--pnp-root`, `--trace-driver-api`, `--console-mirror`) não entram no
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
  num arquivo temporário do QEMU), então as pistas o dividem e cada execução
  começa dele intacto, como o `test-boot` sempre faz; uma execução que passa
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
  (`--no-build --image-dir=build/test-all/imagem-<n>`).
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
  `espera_falha = true` no `[[teste]]` conta a falha à parte, sem reprovar a
  rodada (e avisa quando o teste passa); `coberto_pela_suite = true` tira do
  padrão um teste cujos marcadores as suítes conferem (roda com `--only`).
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
  `--trace-driver-api` mostra cada export chamado (veja o README). Os testes
  `watchdog` e `dxgkrnl` do `components.toml` iniciam assim o watchdog.sys e
  o núcleo gráfico (serviço `DXGKrnl`, com os valores da chave do Windows) e
  esperam `DRIVER_START_COMPLETED name=<serviço> state=4 win32=0`; depois,
  com a CI ainda ativa, a pilha PS/2 passa pela validação
  (`CI_KERNEL_IMAGE_RESULT name=\FS\i8042prt.sys status=0x0`), o serviço de
  teclado lê do i8042prt.sys e o `--hold=30000` mantém o sistema rodando
  30 s sem falha na serial. Uma imagem recusada pela CI falha com o status
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
- **Depurador do kernel**: `cargo xtask debug` compila com `--kd=com2`, abre
  o QEMU com a COM2 num socket TCP local e o prompt do cliente; o protocolo
  remoto do GDB, os símbolos (`kernel.elf` com os nomes do Rust legíveis,
  exports dos PEs desta máquina e os públicos de um PDB já no cache do
  `nt-types`), a pilha pelos frame pointers, o passo por cima (`p`, um
  breakpoint temporário depois do `call`, com o RSP de volta conferido para
  ignorar uma recursão mais funda) e para fora (`gu`, pelo endereço de
  retorno do prólogo ou de RBP + 8), os breakpoints do cliente (`bd`/`be`
  desligam e religam) e os comandos ficam no crate `tools/kd-client`, que o
  `xtask/src/debug` (o prompt) e o depurador gráfico usam;
  `--connect=HOST:PORTA` só conecta (a um `cargo xtask run --kd=com2`, porta
  1234, onde o GDB também entra), e `--launch --no-client [--headless]` só
  compila e abre o QEMU para outro cliente (imprime `KD_READY 127.0.0.1:PORTA`
  e fecha o QEMU quando a entrada padrão fecha). Os testes do cliente
  (`cargo test -p kd-client`) cobrem os pacotes, a resposta de parada, os
  registradores, os símbolos, a pilha sobre uma pilha capturada, o tamanho
  dos `call` e, contra um alvo de mentira num socket local
  (`tools/kd-client/tests/fake_target.rs`), a sessão inteira com os
  breakpoints e o passo por cima numa recursão.
- **Depurador gráfico** (`tools/kd-gui`, binário `opennt-dbg`):
  `cargo run -p kd-gui --release -- --launch` roda o mesmo build e QEMU do
  `cargo xtask debug --launch` e abre a janela; `--connect=HOST:PORTA` entra
  num QEMU aberto. A interface é egui/eframe (Rust puro, backend OpenGL
  `glow`, sem wgpu) com painéis encaixáveis do `egui_dock`: Comando (os
  comandos do prompt de texto), Desmontagem (iced-x86, sintaxe MASM, em
  volta do RIP, com símbolos, destinos dos desvios e a margem que liga e
  tira breakpoints), Fonte (a linha do DWARF do `kernel.elf` pelo
  `addr2line`, só para o código do OpenNT), Registradores (por processador
  ou thread, editáveis com a máquina parada), Memória (hexadecimal e ASCII
  num endereço ou símbolo, editável), Pilha de chamadas, Módulos, Processos
  (com os processadores), Threads (escolher uma mostra os registradores e a
  pilha dela, pelo quadro de troca quando está fora da CPU), Breakpoints
  (software, hardware e vigias, ligar e desligar), DbgPrint e o log da COM1.
  Barra: Parar (Ctrl+B), Continuar (F5), Entrar (F11), Passar (F10), Sair
  (Shift+F11), Reiniciar (fecha o QEMU, recompila e abre de novo) e o estado
  da conexão. O backend (`backend.rs`) fala com o alvo numa thread e publica
  um snapshot por parada; a janela nunca espera o socket. O teste de fumaça
  (`cargo test -p kd-gui --release -- --ignored`, `tests/smoke.rs`) roda o
  backend sem janela: abre o OpenNT com o QEMU sem tela, anexa, confere
  registradores, módulos, pilha, desmontagem e a linha de código, pede a
  parada com a máquina rodando, para num breakpoint em
  `kernel::ntos::ke::run_kernel_tasks`, passa por cima e sai da função até o
  `kmain`, roda um comando e desenha a janela fora da tela. A captura
  `docs/screenshots/kd-gui.png` sai de `opennt-dbg --launch --break-at=EXPR
  --screenshot=ARQ`: o egui roda sem janela e um rasterizador de software
  (`offscreen.rs`) pinta os triângulos do `tessellate` com o atlas das
  fontes, sem GPU.
- **Teste do depurador**: o teste `kd` é um `test-boot` com
  `--kd=com2 --script=xtask/scripts/kd.txt`: o roteiro roda contra a COM2
  em paralelo ao boot e a falha dele derruba o teste. Ele anexa,
  confere o estado do depurador e os processadores congelados, lê e grava
  memória, pede a parada com a máquina rodando, para num breakpoint de
  software no laço principal, confere a saída do DbgPrint do ksecdd.sys real
  e as consultas do OpenNT (com a pilha de uma thread de kernel bloqueada,
  pelo quadro de troca), dá um passo, para num breakpoint de hardware e se
  desliga; o boot segue até o shell, que o roteiro espera na COM1. O boot com `--kd` roda também
  `ntos/test/kernel_debugger.rs` (`KD_EXPORTS_OK`).
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
  WinSta0; ainda não sai: o csrss para no NtCreatePort);
  os de falha são `*** PANIC`, `*** EXCECAO`, `SELFTEST FALHOU` e `*** STOP`
  (a parada do KeBugCheckEx). O `test-boot` procura falhas desde o boot até
  a última saída esperada e, com `--hold=MS`, por mais MS milissegundos.

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
