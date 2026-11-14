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
| `xtask` | build, PE do kernel, imagem de disco, volume NTFS, QEMU, `test-boot` e `status` |

## 2. Árvore do kernel

```
kernel/src/
├── main.rs            entrada (kernel_main), BSS, panic_handler
├── hal/               HAL: portas, serial, CPU, memória física, LAPIC, RTC, heap,
│   │                  ACPI, PCI, firmware, HalPrivateDispatchTable e exports Hal*
│   └── amd64/         código x64: interrupções, anel 3, trampolim dos APs, chamadas
│                      MS-ABI, trampolins dos exports, entradas privadas, serviços
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
│   ├── cm/            Registry
│   │   ├── key/       chaves e serviços Nt/Zw de chave
│   │   └── service/   serviços e drivers (base, canal, RPC)
│   ├── rtl/           a Rtl do NT: strings, Unicode, páginas de código, AVL, bitmap,
│   │   │              exceções, imagens PE, tabelas de átomos (atom), heap (heap)
│   │   └── resource/  recursos de imagens (ldrrsrc) e tabelas de mensagens
│   ├── alpc/          ALPC (connect/, message/, resource/)
│   ├── po/ etw/ kd/ dbgk/ fsrtl/
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

- **As estruturas vêm de `ntos/inc/types`**, geradas a partir dos símbolos do
  ntoskrnl (`build/symbols/ntkrnlmp.pdb`, Windows 10 19041): o mesmo layout com
  que o kernel real foi compilado, `#[repr(C)]`, com `size_of`/`offset_of!`
  conferidos em compilação. Os nomes são os do NT em snake_case (`IoStatus` ->
  `io_status`, `Tail.Overlay.CurrentStackLocation` ->
  `tail.overlay.current_stack_location`; palavras reservadas ganham `_`, como
  `type_`). Membros que o C sobrepõe (uniões anônimas) ficam em vistas
  encadeadas por `Deref`, então o nome resolve direto (`thread.state`,
  `iosb.pointer`). O diretório é gerado e não se edita à mão, com uma
  exceção: `types/wdk.rs`, mantido à mão no mesmo estilo, com as estruturas
  públicas do WDK/SDK que não constam dos símbolos (OB_CALLBACK_*, classes de
  informação dos Nt*, atributos ALPC...), cada uma citando o cabeçalho de
  origem.
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
| 0xFFFFA000_00000000 | 320 | pool executivo, dump, memória contígua e independente, visões de sistema, VirtualAlloc de kernel, pilhas de kernel das threads (0xFFFFA007_00000000..0xFFFFA008_00000000) |
| 0xFFFFB000_00000000 | 352 | **mapa direto**: toda a faixa física [0, 4 GB) em `DIRECT_MAP_BASE + PA` |
| 0xFFFFC000_C0000000 | 384 | **janela do heap**: heap do kernel (kmalloc, o alocador do Rust) e a arena dos convidados (IRPs, DEVICE_OBJECTs, MDLs, ExAllocatePool2...) sobre os frames de 32 MB a 96 MB |
| 0xFFFFF780_00000000 | 495 | KUSER_SHARED_DATA (visão do kernel) |
| 0xFFFFF800_00000000 | 496 | KPCR, pool de dados, a **imagem do kernel** (0xFFFFF800_40000000), a pilha de boot (topo em 0xFFFFF800_41200000) e a janela de imagens de kernel (0xFFFFF801_00000000..0xFFFFF802_00000000) |

**Imagem do kernel.** O ntoskrnl é ligado na sua VA de sistema, como no NT:
a ImageBase do PE é `KERNEL_VIRTUAL_BASE` = 0xFFFFF800_40000000 (cabeçalhos
na primeira página, `.text` em +0x1000), e é essa base que a lista de módulos
carregados, o KDDEBUGGER_DATA64 e o `RtlPcToFileHeader` veem. O stage2 lê o
arquivo do disco para os frames a partir de 1 MB (offsets do arquivo == RVAs),
confere o cabeçalho (ImageBase, SizeOfImage, entrada) e mapeia exatamente
SizeOfImage páginas de 4 KB de supervisor, RW e executáveis na ImageBase, com
tabelas fixas em 0x83000-0x8BFFF (PDPT, PD e sete PTs). A pilha de boot é
outra VA de sistema na mesma PD: 383 páginas RW e NX terminando em
`BOOT_STACK_TOP`, sobre os frames logo abaixo de 15,5 MB, com uma página de
guarda sem mapeamento embaixo (PT em 0x8C000). O stage2 carrega o GDTR pela VA
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
`usermode::block()` e `pcr::current()`. No M0 só o BSP executa o anel 3
(assert em `exec_user_mode`/`exec_user_context`); os APs têm KPCR e bloco,
mas não têm TSS, LSTAR nem pilha reserva. O autoteste
`ntos/test/multiprocess/per_cpu.rs` confere os blocos distintos de cada CPU
e uma syscall de teste que devolve gs:[10h] igual ao RSP do usuário.

**Pilhas de kernel por thread.** Toda thread que executa tem pilha de kernel
própria, do `mm/kernel_stack.rs` (o MmCreateKernelStack/MmDeleteKernelStack):
uma reserva fixa de 256 KB de VA na janela `KERNEL_STACK_BASE..TOP`, com a
pilha no topo (64 KB; 128 KB na grande) em frames do PFN não contíguos, PTEs
de supervisor RW e NX, e a página logo abaixo do StackLimit sem PTE (a
guarda). `ps::process::create_kernel_thread(.., Some(pilha))` fica dono dela e
preenche os campos reais da KTHREAD do 19041: StackBase (o topo), StackLimit,
InitialStack = StackBase - 0x30 (o KERNEL_STACK_CONTROL, com CurrentStackBase
e ActualLimit) e KernelStack = InitialStack; com `None` a KTHREAD descreve a
pilha de boot (o kmain, o System e os contextos de kernel do escalonador
rodam nela). Usam pilha própria as threads de usuário (a primeira, da
criação em `ps/create.rs`, e as de NtCreateThreadEx), as threads de
sistema nativas (PsCreateSystemThread, que antes tiravam a pilha da arena) e
os níveis dos contextos de KeAllocateCalloutStackEx. Como no KiSwapContext, o
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
da syscall, KPCR.UserRsp, NtContinue, posse de execução nativa). O
despachante de `ps/user/threads.rs` segue com as outras threads, sonda a
espera no contexto da bloqueada (thread corrente e CR3 dela) e, quando ela
conclui, retoma o
serviço na pilha dela (`switch_to` → `usermode::resume_kernel_context`, que
monta um quadro de despachante novo e entra no quadro salvo) em vez de entrar
no anel 3; a syscall termina o intervalo como qualquer outra. Passam por aí
KeWaitForSingleObject/Multiple (alertáveis ou não), KeDelayExecutionThread,
fast/guarded mutex, ERESOURCE, push locks e rundown
(`context_switch::wait_until`/`acquire_until`); fora de uma syscall (boot,
threads de sistema, APCs e conclusões drenadas pelo despachante) a espera
continua girando o pump. Como no NT, esperar de fato com prazo não nulo em
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
bloqueada (THREAD_IS_TERMINATING, desfeita na própria pilha).

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
  STATUS_INVALID_PARAMETER. Vistas de seção usam a mesma escolha.
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
executáveis (o pool não paginado comum do NT executa, e a arena guarda
pequenas rotinas de conclusão geradas em tempo de execução).
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
  apontam para PDPTs de supervisor (cerca de 1 MB do PFN).
- As PDPTs entram no conjunto `permanent` de `paging.rs`: nunca voltam ao
  PFN, nem quando a última página do slot é desfeita.
- Depois do congelamento, criar ou alterar uma entrada de sistema da PML4 é
  erro fatal (assert em `pd_entry_address`), e `map_page`/`map_large_page`
  recusam página de usuário na metade de sistema. O que o kernel mapeia
  depois só muda os níveis de baixo, em tabelas compartilhadas.
- Por isso uma raiz nova (`process_address_space::create_root`) copia
  PML4[257..512) uma única vez e fica coerente para sempre. Ela ganha a
  própria auto-referência em [256] e começa com a metade de usuário vazia.
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
  APs ficam na raiz do System. O rastreador de frames só acompanha as tabelas
  alcançadas pela PML4 do boot (a metade de sistema inteira e a metade de
  usuário do System): a PML4 de um processo, as tabelas de usuário dela e as
  folhas dessas tabelas ficam fora dele, sem notificação e sem PteAddress no
  banco nativo de PFNs. O mapeamento recursivo confere a auto-referência da
  raiz carregada, não a da PML4 do boot.
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
- As imagens de usuário ficam na ImageBase do cabeçalho quando a faixa está
  livre na metade de usuário (ou na primeira faixa livre a partir de 64 KB,
  relocadas), também sobre frames do PFN.

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
- **Errata Manager** (`em/`): provedores e avaliação de regras sobre o
  banco do INF de errata. O carregador do OpenNT não entrega o INF, então
  o banco é vazio como no ntoskrnl sem ele: só o provedor sem entradas nem
  callbacks é registrado, e as regras não existem (STATUS_NOT_FOUND com
  STATE_UNKNOWN).
- **Trava e energia do KD** (`kd/power.rs`): KdDebuggerLock em
  DISPATCH_LEVEL, a lista dos tratadores de energia do transporte e, com o
  KdPitchDebugger de um boot sem /DEBUG, KdPowerTransitionEx sem efeito e
  KdDisableDebugger com STATUS_DEBUGGER_INACTIVE; DbgCommandString é o
  serviço 5 do `int 0x2D` num corpo nativo.
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
    SecurityProcedure (o SeDefaultObjectMethod quando o tipo não traz uma) e
    QueryNameProcedure no ObQueryNameString. Open e Close rodam anexados ao
    processo do handle. A ParseProcedure pertence à busca de nomes do
    namespace (`ob/handles/namespace.rs`) e ainda não é chamada.
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
    O descritor de uma thread é o do processo dela (os dois vêm do DACL
    padrão do token primário do processo), e NtGetNextThread usa o mesmo.
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
  TebAddress e ImageInfo; recusa com STATUS_NOT_SUPPORTED DebugObject,
  Token, SecureProcess, JobList e UmsThread; aceita sem efeito, no log, os demais que o kernel32
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
    da montagem). O leitor NTFS do kernel continua dono do disco como D:,
    então as escritas do file system ficam numa sobreposição em memória por
    página de 4 KB, que as leituras do volume aplicam; o disco não muda.
  - O `--start-driver` de um driver de file system (Type 2) cria o volume e
    abre e lê um arquivo conhecido pelos exports
    (`ntos/test/file_system_mount.rs`); a fase 6 cobre o caminho com dois
    file systems sintéticos.
- **Cadeia smss -> csrss real** (`--initial-process=smss`,
  `init/boot_config.rs::SMSS_BOOT`): o primeiro processo de usuário é o
  `\SystemRoot\System32\smss.exe` real (`init/initial_process.rs`), criado
  pelo caminho único com PS_PROTECTION WinTcb-Light (0x61) e
  BreakOnTermination, com a ntdll real. O build põe no volume os binários da
  cadeia (smss, csrss, csrsrv, basesrv, winsrv, sxssrv, npfs.sys, msfs.sys e
  as DLLs que eles importam), e o kernel semeia o Registro que eles leem: a
  chave Session Manager (`cm/session_manager.rs`: SubSystems com a linha do
  csrss, KnownDLLs, DOS Devices, Environment; sem Kmode, BootExecute nem
  arquivos de paginação), os serviços Npfs e Msfs e o
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
  pseudo-handles de processo e thread), a ObjectSessionObjectInformation
  do NtSetInformationObject e a duplicação de handles do Object Manager
  (com DUPLICATE_NO_RIGHTS_UPGRADE). O marcador `SMSS_CSRSS_OK` sai quando o csrss.exe criado
  por um smss pede o primeiro serviço do win32k
  (`ex/service_table.rs::out_of_range` -> `initial_process::win32k_requested`)
  com o smss inicial e o csrss vivos. Hoje o csrss vai até carregar o
  basesrv.dll e para na inicialização dele (a SystemTimeOfDayInformation
  ainda não tem resposta), antes do winsrv e do win32k.
- O `xtask` lê três fontes do kernel por `#[path]`:
  `ntos/mm/kernel_data_layout.rs` (`.kdata`/`.edata` do PE e páginas de status),
  `ntos/init/export_names.rs` e `ntos/init/native_export_layout.rs` (a EAT do
  PE). O `kernel/build.rs` inclui `ntos/ke/services.rs` para gerar a ntdll de
  bring-up.

## 5. Testes

- **Autotestes no QEMU** ficam em `ntos/test/` e rodam conforme
  `--kernel-test-scope`. A suíte completa:
  `cargo xtask test-boot PHASE3_SELFTEST_OK 240000 --kernel-test-scope=all --smp=4 --expect=PHASE4_SELFTEST_OK ... --expect=PHASE6_SELFTEST_OK --expect=MULTIPROCESS_OK --expect=PHASE7_SELFTEST_OK --expect=KBDTEST_OK --expect=SELFTEST_OK`
  (os `--expect` são procurados em ordem, cada um depois do anterior: o
  `MULTIPROCESS_OK` sai dentro da fase 7, antes do `PHASE7_SELFTEST_OK`).
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
  esperam `DRIVER_START_COMPLETED name=<serviço> state=4 win32=0`.
- **Marcadores**: `HELLO_KERNEL_OK`, `KERNEL_RS_OK`, `SELFTEST_OK`,
  `PHASE3_SELFTEST_OK` a `PHASE7_SELFTEST_OK`, `MULTIPROCESS_OK` (o
  NtCreateUserProcess de um processo pai real, na fase 7), `KBDTEST_OK`,
  `[shell] pronto`, `FILE_SYSTEM_MOUNT_OK name=<serviço>` (um arquivo do
  volume aberto e lido pelo file system real iniciado com `--start-driver`);
  `[shell] pronto`, `SMSS_CSRSS_OK` (com `--initial-process=smss`: o
  csrss.exe real criado pelo smss.exe real chega ao win32k;
  `cargo xtask test-boot SMSS_CSRSS_OK 300000 --initial-process=smss --build-dir=build/smss --smp=1`);
  os de falha são `*** PANIC`, `*** EXCECAO` e `SELFTEST FALHOU`.

## 6. Documentação e status

| Lugar | Conteúdo |
| --- | --- |
| `README.md` | o que é o OpenNT, estado por fase, como compilar, rodar e testar |
| `docs/ROADMAP.md` | fases e estado de cada componente; gerado por `cargo xtask status` |
| `docs/ARQUITETURA.md` | este documento |
| `docs/status/components.toml` | dados editados à mão: fases, componentes, testes, subsistemas |
| `docs/status/modulos-planejados.txt` | módulos planejados por subsistema |
| `docs/status/ntoskrnl-exports.def` | cache dos nomes exportados pelo `ntoskrnl.exe` 19045 |
| `docs/status/*.svg`, `docs/site/` | gerados por `cargo xtask status`; não editar |

O `cargo xtask status` acha o arquivo Rust de cada módulo planejado pela pasta
e pelo nome (`ntos/ob/object_manager` → `.../ob/object_manager.rs`), por um
`pub mod <nome> {` dentro de um arquivo do componente, ou pela tabela
`[correspondencias]` do `components.toml` (usada quando o módulo foi para uma
subpasta com outro nome, como `ntos/ex/wnf_name` → `ntos/ex/wnf/name.rs`).

## 7. O nome OpenNT nos arquivos

Banners, prompt do shell (`OpenNT> `), mensagens do `xtask`, rótulo do volume
em memória, arquivo de paginação (`/$opennt-pool-page-N.sys`) e as variáveis
de build (`OPENNT_USER_PROGRAM`, `OPENNT_KERNEL_TEST_SCOPE`,
`OPENNT_CONSOLE_MIRROR`, `OPENNT_START_DRIVER`, `OPENNT_TRACE_DRIVER_API`)
usam o nome OpenNT. Continuam iguais: os marcadores de boot, o nome do binário
`kernel`, os artefatos `build/kernel.elf`, `kernel.pe` e `os.img` e os nomes
dos pacotes (`kernel`, `boot`).

## 8. Pontos em aberto

- Alguns grupos de exports ainda misturam componentes e moram no `exports.rs`
  de um só: `driver_helpers`, `io_diagnostics` e `x86bios_sleep_misc` em `io`,
  `ke_ex_sync` em `ke`, e rotinas Se*/Ke* que ficaram em `ps`. Falta separá-los
  pelo prefixo, conforme a seção 3.1.
- `rtl/` (suporte do kernel em Rust) e `ntos/rtl/` (a Rtl do NT) ainda têm o
  mesmo nome.
- `ntos/ps/user/` reúne os serviços Nt* do modo usuário; no NT cada serviço
  mora no seu componente (NtCreateFile no Io, NtAllocateVirtualMemory no Mm).
- Nome do binário: manter `kernel` ou gerar `ntoskrnl.exe`.
