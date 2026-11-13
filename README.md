# OpenNT

[![Exports do ntoskrnl.exe do Windows 10 22H2 cobertos pelo OpenNT](docs/status/selo-ntoskrnl.svg)](docs/site/ntoskrnl.html)
[![Componentes e drivers que funcionam no OpenNT](docs/status/selo-componentes.svg)](docs/site/componentes.html)

**OpenNT** é um kernel x86-64 escrito em Rust `no_std`, com a arquitetura do
Windows NT, capaz de **carregar e iniciar drivers `.sys` reais do Windows**.
HAL, nanokernel e executive (Ke, Mm, Io, Ob, Ps, Se, Ex, Cm, Rtl, ALPC, Po,
Etw…) são implementados do zero; um carregador de PE32+ mapeia os binários da
Microsoft, resolve suas importações contra a tabela de exports do próprio
kernel e executa o `DriverEntry` com os mesmos layouts de estrutura, NTSTATUS
e convenção de chamada do NT. O boot (setor de boot + stage2) é Assembly
montado pelo próprio `rustc`; todo o resto é Rust, sem bibliotecas externas.
O `cargo xtask` cuida do build, da imagem de disco, do QEMU e dos testes.

Não é um emulador nem uma máquina virtual: é um núcleo de sistema operacional
que fala a mesma ABI binária que os drivers do Windows esperam.

```
┌── um .sys real do Windows (ex.: i8042prt.sys, kbdclass.sys, cng.sys) ──┐
│  importa ExAllocatePoolWithTag, IoCreateDevice, KeInitializeSpinLock…  │
└───────────────────────────────┬───────────────────────────────────────┘
                                 │ carregado pelo loader de PE do OpenNT
                 ┌───────────────▼────────────────┐
                 │  OpenNT — kernel NT em Rust     │
                 │  Ke · Mm · Io · Ob · Ps · Se    │
                 │  Ex · Cm · Rtl · HAL · loader   │
                 └───────────────┬────────────────┘
                                 │ roda em 64 bits, SMP, no QEMU
                        ┌────────▼────────┐
                        │  x86-64 / QEMU  │
                        └─────────────────┘
```

## O que já funciona

- **Boot x86-64 e SMP.** O sistema sai da BIOS, entra em modo de 64 bits, monta
  IDT/GDT, calibra o timer do LAPIC (100 Hz) e acorda os outros processadores
  (4 CPUs no QEMU).
- **Executive do NT.** Banco de páginas físicas, pool, KPCR, IRQL, DPCs, APCs,
  timers, o dispatcher e processos/threads com `EPROCESS`/`KTHREAD` reais; o
  Object Manager com namespace (`\Device`, `\Driver`, `\GLOBAL??`, `\FS`, `C:`…),
  handles, callbacks, push locks e rundown; tokens e segurança; Configuration
  Manager (Registro); ETW.
- **Drivers reais do Windows carregados e iniciados**, com a `ci.dll` original
  validando a integridade das imagens:
  - **Teclado de ponta a ponta:** `i8042prt.sys` + `kbdclass.sys` da Microsoft —
    o shell recebe as teclas pela pilha PnP real.
  - **Armazenamento:** `ataport`, `atapi`, `disk`, `classpnp`, `mountmgr`,
    `wmilib`; **mouse:** `mouclass`; **criptografia:** `cng.sys`.
- **Mais de 900 símbolos** que o `ntoskrnl.exe` do Windows 10 22H2 exporta aos
  drivers já são oferecidos pelo OpenNT (de ~3.070 no total), implementados com
  a semântica real de cada função.
- **NTFS** de leitura e escrita, sistema de arquivos em memória, carregador de
  PE32+ com relocações e IAT, controle de serviços (`sc`) e processos de modo
  usuário com SYSCALL/SYSRET.
- **Suíte de autotestes** que compila sem avisos e passa inteira no QEMU
  (`cargo xtask test-boot`), cobrindo cada subsistema e cada export novo.

## Estado por fase

O OpenNT avança em fases, descritas no [roadmap](docs/ROADMAP.md). Cada fase
termina com o kernel compilando, bootando no QEMU e passando nos autotestes
daquela parte.

| Fase | Escopo | Estado |
| --- | --- | --- |
| 1 — base | boot, HAL, nanokernel, relógio, escalonador, sistema de arquivos em memória, vídeo, console, teclado, shell, `xtask` | ✅ concluída |
| 2 — memória e CPU | páginas físicas, mapeamento recursivo, pool, imagens carregadas, KUSER_SHARED_DATA, KPCR, IRQL, DPC, multiprocessador, ACPI, estruturas do NT | ✅ concluída |
| 3 — objetos e executive | Object Manager, Rtl, Ex, Se, Ps | ✅ concluída |
| 4 — I/O e armazenamento | I/O Manager, ACPI/PCI, energia, ETW, barramentos, disco ATA, NTFS | ✅ concluída |
| 5 — Registro e serviços | Configuration Manager, `sc` | ✅ concluída |
| 6 — loader PE e ntoskrnl | carregador de PE, funções exportadas pelo kernel, drivers reais, KsecDD | 🚧 em andamento |
| 7 — modo usuário | processos e threads de usuário, ALPC, ntdll/KERNEL32 reais | 🚧 em andamento |

As fases 6 e 7 seguem crescendo: cada driver real que se tenta carregar revela
as funções do `ntoskrnl` que ainda faltam, implementadas uma a uma com a
semântica do NT e cobertas por autoteste.

## Compatibilidade — páginas geradas do código

Três páginas HTML estáticas (sem rede, abra os arquivos de `docs/site/` no
navegador) mostram onde o OpenNT está, sempre a partir do código:

- **[Visão geral](docs/site/index.html)** — os números principais, o que já
  roda e a linha do tempo das fases, com um glossário dos termos.
- **[Exports do kernel](docs/site/ntoskrnl.html)** — quantas das ~3.070 funções
  e variáveis do `ntoskrnl.exe` do Windows 10 22H2 o OpenNT oferece, por prefixo
  (Ke, Mm, Ob, Ps, Io, Ex, Rtl, Se, Zw/Nt…), com busca e paginação.
- **[Componentes e drivers](docs/site/componentes.html)** — o que cada parte faz,
  se já funciona, qual autoteste a cobre e em que fase entra.

![Exports do ntoskrnl.exe por prefixo](docs/status/ntoskrnl-por-prefixo.svg)

Para regenerar páginas, selos, gráfico e roadmap depois de mudar o kernel:

```powershell
cargo xtask status   # não compila o kernel
```

A lista de referência dos exports do Windows fica em
[`docs/status/ntoskrnl-exports.def`](docs/status/ntoskrnl-exports.def) (só os
nomes; nenhum binário da Microsoft entra no repositório). O estado, os testes e
a fase de cada componente ficam em
[`docs/status/components.toml`](docs/status/components.toml), editado à mão e
conferido a cada geração.

## Arquitetura

O código segue a árvore do kernel do Windows NT: um diretório por componente do
executive, cada um dono do seu código **e das rotinas que exporta**
(`ntos/<componente>/exports.rs`). A HAL concentra o hardware e o código x64; o
carregador de PE fica no Mm, como o `sysload` do NT; os autotestes rodam dentro
do kernel, no QEMU.

| Caminho | Responsabilidade |
| --- | --- |
| `boot/` | Setor de boot e stage2 (modo real → protegido → 64 bits) |
| `kernel/src/hal/` | HAL: portas, serial, CPU, memória física, LAPIC, heap, RTC, ACPI, PCI, `HalPrivateDispatchTable`; código x64 em `hal/amd64/` |
| `kernel/src/rtl/` | Suporte do kernel em Rust: serial, locks, erros com NTSTATUS, tempo |
| `kernel/src/nano/` | Interrupções, canais de mensagens, registro de serviços |
| `kernel/src/ntos/` | Executive, um diretório por componente: `ke`, `mm`, `io`, `ob`, `ps`, `se`, `ex`, `cm`, `rtl`, `alpc`, `po`, `etw`, `kd`, `fsrtl` |
| `kernel/src/ntos/inc/` | Layouts das estruturas do WDK e NTSTATUS |
| `kernel/src/ntos/init/` | Boot em fases, configuração de build e a tabela de exports do ntoskrnl |
| `kernel/src/ntos/test/` | Autotestes de boot (`phase3.rs`…`phase7.rs`, `self_test.rs`) |
| `kernel/src/drivers/` | VGA, console, teclado PS/2, barramentos, disco ATA e sistemas de arquivos (`drivers/fs/`: RAMFS e NTFS) |
| `kernel/src/shell/`, `kernel/src/apps/` | Shell e programas de exemplo |
| `xtask/` | Build, PE32+ do kernel, `os.img`, QEMU, `test-boot`, `status` |
| `docs/` | Roadmap, arquitetura e páginas de compatibilidade |

A árvore completa, as regras de dependência de cada componente e as convenções
estão em **[docs/ARQUITETURA.md](docs/ARQUITETURA.md)**.

## Requisitos

- **Rust nightly** com `rust-src`, `llvm-tools-preview` e o alvo
  `x86_64-unknown-none`. O [rust-toolchain.toml](rust-toolchain.toml) declara
  tudo; o rustup instala o que faltar no primeiro build.
- **QEMU** (`qemu-system-x86_64`). O `xtask` procura na variável `QEMU`, depois
  no `PATH` e em `C:\Program Files\qemu`.

Não são necessários Node.js, Python, NASM nem Zig.

## Compilar, executar e testar

```powershell
# Compila boot + kernel e monta build/os.img.
cargo xtask build

# Shell interativo numa janela do QEMU; a serial fica neste terminal.
cargo xtask run

# Boot sem tela até um marcador da serial (padrão KERNEL_RS_OK).
cargo xtask test-boot

# Suíte completa de autotestes.
cargo xtask test-boot SELFTEST_OK 60000 --kernel-test-scope=all --build-dir=build/tests

# Digita no shell pelo monitor do QEMU e confere a saída.
cargo xtask test-boot KERNEL_RS_OK 120000 "--keys=run hello\nps\n" "--expect== 42"

# Páginas de compatibilidade, selos e roadmap.
cargo xtask status
```

Opções de build: `--release`, `--build-dir=DIR`, `--kernel-test-scope=none|all`,
`--start-driver=NOME` (inicia o serviço pelo gerenciador de serviços, com a
integridade de código ativa, e imprime `DRIVER_START_COMPLETED`),
`--trace-driver-api` (mostra cada chamada de API do driver enquanto ele inicia:
objetos abertos, rotinas pedidas ao `MmGetSystemRoutineAddress`, valores do
Registro e texto formatado). Opções de máquina: `--accel=tcg|whpx`,
`--memory-mb=N` (padrão 4096), `--smp=N` (padrão 4). Em `--keys`, `\n` digita
Enter; `--expect` pode se repetir. O `test-boot` falha se a serial mostrar
`*** PANIC`, `*** EXCECAO` ou `SELFTEST FALHOU`.

Para carregar um driver real, o build copia do Windows da própria máquina os
`.sys`/`.dll` de que ele precisa (hal.dll, i8042prt, kbdclass, atapi, cng.sys,
ci.dll…) e os coloca no volume NTFS da imagem. **Nenhum binário da Microsoft ou
de terceiros entra no repositório.**

Comandos do shell: `help`, `version`, `clear`, `echo`, `mem`, `ls`, `cat`,
`write`, `rm`, `run hello`, `spawn pisca`, `ps`, `kill`, `sc`, `halt`.

## Fora do escopo

- Compatibilidade geral com Windows, drivers de GPU ou jogos. O resultado de um
  driver ou de uma suíte não comprova compatibilidade com outros programas.
- Binários de terceiros nunca entram no repositório; o OpenNT os lê da própria
  máquina em tempo de build.
