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
│   ├── ex/            executive: push locks, rundown, lookaside, callbacks, pool
│   │   ├── wnf/       Windows Notification Facility
│   │   └── license/   licenciamento
│   ├── cm/            Registry
│   │   ├── key/       chaves e serviços Nt/Zw de chave
│   │   └── service/   serviços e drivers (base, canal, RPC)
│   ├── rtl/           a Rtl do NT: strings, Unicode, AVL, bitmap, exceções, imagens PE
│   │   └── resource/  recursos de imagens (ldrrsrc)
│   ├── alpc/          ALPC (connect/, message/, resource/)
│   ├── po/ etw/ kd/ dbgk/ fsrtl/
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
| 0xFFFFA000_00000000 | 320 | pool executivo, dump, memória contígua e independente, visões de sistema, VirtualAlloc de kernel |
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
  MiCreatePebOrTeb. Como a tabela de páginas ainda é uma só, a escolha vê o
  que todos os processos ocupam (`memory::occupied`) e as PTEs reais.
- **Imagens de usuário** carregam na ImageBase do cabeçalho quando a faixa
  está livre (um .exe em 0x1_4000_0000) e, se não estiver, na primeira faixa
  livre, relocadas (STATUS_IMAGE_NOT_AT_BASE nas vistas de imagem). A imagem
  principal de um processo é desfeita quando ele termina, e a VA volta ao
  livre para o próximo.

O stage2 monta o mapa direto (páginas de 2 MB de supervisor, RW e NX; tabelas
em 0x76000-0x7AFFF) antes de entrar no kernel. A regra:

- **Endereço físico nunca é ponteiro.** Quem tem um PA usa `hal::physical`,
  que traduz pelo mapa direto e para o sistema se receber algo fora da faixa
  física (uma VA, por exemplo). Isso vale para PTEs e tabelas (`paging.rs`),
  descritores de PFN, frames do PFN, MMIO (LAPIC, texto VGA), tabelas ACPI,
  o handoff do stage2 (E820, flags, firmware), as células fixas de baixo
  nível (0x81000, a IDT em 0x82000, a página de controle do anel 3 em
  0x8F000) e os dados do trampolim dos APs. A IDT, a GDT do boot e as pilhas dos APs são carregadas
  pela VA do mapa direto; MmMapIoSpace e os mapeamentos físicos da HAL
  devolvem VAs dele.
- **Endereço virtual** é acessado por `mm/guest_memory.rs` (memória confiável
  ou sondada) ou pelos MOVs de `hal::volatile`.
- **Stubs em assembly** carregam a VA da página de células num registrador
  (`movabs`) e endereçam por deslocamento; a entrada de syscall troca a pilha
  por `MOV moffs64`, sem registrador livre.
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
- Estado global fica atrás de `SpinLock` (`rtl::sync`). Estado lido muito e
  mudado em operações longas, como um volume NTFS, fica atrás de
  `SharedLock`, o papel do ERESOURCE: leituras compartilhadas, mutações
  exclusivas, readquirível por quem já o possui.
- **Estado por processo**: o que no NT mora no EPROCESS e o OpenNT ainda não
  guarda numa estrutura do NT fica em `ps/user/process_state.rs`, um
  `ProcessState` por EPROCESS (o System inclusive), criado por
  `ps::process::create_process` antes da lista ativa e destruído por
  `terminate_process` depois dela. Estado novo de processo entra ali, não num
  global de `ps/user/state.rs`.
- O `xtask` lê três fontes do kernel por `#[path]`:
  `ntos/mm/kernel_data_layout.rs` (`.kdata`/`.edata` do PE e páginas de status),
  `ntos/init/export_names.rs` e `ntos/init/native_export_layout.rs` (a EAT do
  PE). O `kernel/build.rs` inclui `ntos/ke/services.rs` para gerar a ntdll de
  bring-up.

## 5. Testes

- **Autotestes no QEMU** ficam em `ntos/test/` e rodam conforme
  `--kernel-test-scope`. A suíte completa:
  `cargo xtask test-boot PHASE3_SELFTEST_OK 240000 --kernel-test-scope=all --smp=4 --expect=PHASE4_SELFTEST_OK ... --expect=KBDTEST_OK --expect=SELFTEST_OK`.
- **Drivers reais**: `--start-driver=<serviço>` sobe um driver do volume e
  `--trace-driver-api` mostra cada export chamado (veja o README).
- **Marcadores**: `HELLO_KERNEL_OK`, `KERNEL_RS_OK`, `SELFTEST_OK`,
  `PHASE3_SELFTEST_OK` a `PHASE7_SELFTEST_OK`, `KBDTEST_OK`, `[shell] pronto`;
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
