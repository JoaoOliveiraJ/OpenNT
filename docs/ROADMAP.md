# Roadmap do OpenNT

<!-- Gerado por `cargo xtask status` a partir de docs/status/components.toml. Não edite à mão. -->

O OpenNT avança em fases. Cada fase termina com o kernel compilando, iniciando no QEMU e passando nos testes automáticos daquela parte.

**Estados dos componentes.** *Funciona*: o código existe e um teste automático de boot passa por ele. *Parcial*: só uma parte existe, ou o código existe mas ainda não tem teste automático. *Planejado*: ainda não implementado. *Fora do escopo*: fora do roadmap atual. A coluna *Teste automático* diz qual teste cobre o item.

| Fase | Tema | Estado |
| --- | --- | --- |
| 1 | base | concluída |
| 2 | memória e CPU | concluída |
| 3 | objetos e executive | concluída |
| 4 | I/O e armazenamento | concluída |
| 5 | Registro e serviços | concluída |
| 6 | loader PE e ntoskrnl | em andamento |
| 7 | modo usuário | em andamento |

Hoje: **18 de 37** componentes funcionam; **551 de 773** módulos do plano têm código (537 completos e 14 parciais; isso mede código escrito, não testado); o kernel exporta **1.001 dos 3.070** nomes do `ntoskrnl.exe` do Windows 10 22H2 (32,6%).

Detalhes nas páginas [Componentes e drivers](site/componentes.html), [Testes](site/testes.html), [Módulos do kernel](site/modulos.html) e [Exports do ntoskrnl](site/ntoskrnl.html).

## Fase 1 — base (concluída)

Boot pela BIOS até o modo de 64 bits, HAL, nanokernel (interrupções, canais de mensagens, serviços), relógio, escalonador cooperativo, sistema de arquivos em memória, vídeo, console, teclado, shell e a ferramenta de build e testes (cargo xtask).

| Componente | Estado | Teste automático |
| --- | --- | --- |
| Boot em 64 bits | Funciona | Entrada no kernel, Boot completo |
| Interrupções e timer | Funciona | Boot completo, Autoteste do kernel |
| Vídeo VGA em modo texto | Funciona | Boot completo |
| Teclado PS/2 | Funciona | Teste do shell |
| Arquivos em memória | Funciona | Autoteste do kernel, Autoteste de objetos e executive |
| Shell | Parcial | Teste do shell |
| Programas hello e pisca | Funciona | Autoteste do kernel, Teste do shell |

## Fase 2 — memória e CPU (concluída)

Banco de páginas físicas, mapeamento recursivo, pool do kernel, variáveis exportadas, imagens carregadas, KUSER_SHARED_DATA, KPCR, IRQL, DPCs, multiprocessador, ACPI, estruturas do NT e acesso à memória de convidado.

| Componente | Estado | Teste automático |
| --- | --- | --- |
| Gerência de memória | Funciona | Autoteste do kernel |
| Multiprocessador (SMP) | Funciona | Autoteste do kernel |

## Fase 3 — objetos e executive (concluída)

Object Manager (tipos, handles, namespace, callbacks), biblioteca de runtime, Executive (locks, rundown, listas lookaside, callbacks), segurança (SIDs, ACLs, descritores, tokens) e processos e threads com as estruturas reais do NT.

| Componente | Estado | Teste automático |
| --- | --- | --- |
| Processos e threads | Funciona | Autoteste do kernel, Autoteste de objetos e executive |
| Sincronização e despacho | Funciona | Autoteste de objetos e executive, Autoteste do kernel |
| Gerenciador de objetos e namespace | Parcial | Autoteste de objetos e executive |
| Segurança e tokens | Parcial | Autoteste de objetos e executive |

## Fase 4 — I/O e armazenamento (concluída)

I/O Manager, ACPI e PCI, gerência de energia, ETW, drivers de barramento, disco ATA e NTFS.

| Componente | Estado | Teste automático |
| --- | --- | --- |
| I/O Manager | Parcial | Autoteste de I/O e armazenamento, Teclado real |
| Console | Parcial | Boot completo, Teste do shell |
| Barramento PCI | Parcial | Autoteste de I/O e armazenamento |
| Dispositivos da placa-mãe | Parcial | Autoteste de I/O e armazenamento |
| Disco ATA (PIO) | Parcial | Autoteste de I/O e armazenamento |
| NTFS | Parcial | Autoteste de I/O e armazenamento |

## Fase 5 — Registro e serviços (concluída)

Configuration Manager (hives, chaves e valores) e o controle de serviços e drivers (sc).

| Componente | Estado | Teste automático |
| --- | --- | --- |
| Registro | Parcial | Autoteste de Registro e serviços |
| sc (controle de serviços) | Parcial | Autoteste do modo usuário |

## Fase 6 — loader PE e ntoskrnl (em andamento)

Carregador de PE, funções exportadas pelo kernel, carga dos drivers reais do Windows (i8042prt, kbdclass, cng.sys) e KsecDD.

| Componente | Estado | Teste automático |
| --- | --- | --- |
| Carregador de PE e exports do kernel | Parcial | Autoteste do carregador de PE e do ntoskrnl, Boot completo |
| KsecDD | Planejado | — |
| hal.dll | Funciona | Boot completo, Autoteste do kernel |
| i8042prt.sys | Funciona | Teclado real, Teste do shell |
| kbdclass.sys | Funciona | Teclado real, Teste do shell |
| mouclass.sys | Funciona | Teclado real |
| atapi.sys e ataport.sys | Funciona | Boot completo, Autoteste do kernel |
| disk.sys e classpnp.sys | Funciona | Boot completo, Autoteste do kernel |
| mountmgr.sys | Funciona | Boot completo, Autoteste do kernel |
| cng.sys | Funciona | Boot completo, Autoteste do kernel |
| Drivers de teste do WDK | Planejado | — |
| watchdog.sys | Parcial | — |

## Fase 7 — modo usuário (em andamento)

Processos e threads de usuário, comunicação ALPC, chamadas de sistema e as bibliotecas ntdll e KERNEL32 reais.

| Componente | Estado | Teste automático |
| --- | --- | --- |
| Modo usuário | Parcial | Autoteste do modo usuário |
| ntdll.dll, KERNEL32 e KERNELBASE | Planejado | — |
| Executáveis .exe (comando exec) | Planejado | — |

## Sem fase definida

| Componente | Estado | Teste automático |
| --- | --- | --- |
| vgk.sys | Parcial | — |
