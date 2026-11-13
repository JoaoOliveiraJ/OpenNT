# Arquitetura do OpenNT

Como o código do OpenNT está organizado. A árvore segue a do kernel do
Windows NT: cada componente do executive (Ke, Mm, Io, Ob, Ps, Se, Ex, Cm,
Rtl...) mora na sua pasta e é dono do próprio código e das rotinas que
exporta; a HAL, os drivers e a inicialização ficam separados, como no NT.

## 1. Crates

| Crate | Papel |
| --- | --- |
| `boot` | setor de boot e stage2 em `global_asm!` (modo real → protegido → 64 bits) |
| `kernel` | binário `no_std` ligado em 0x101000 por `kernel/link.ld` e empacotado pelo `xtask` como PE32+ de base fixa 0x100000 |
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
