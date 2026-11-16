# Roadmap do OpenNT

<!-- Gerado por `cargo xtask status` a partir de docs/status/components.toml. Não edite à mão. -->

O OpenNT avança em fases. Cada fase termina com o kernel compilando, iniciando no QEMU e passando nos testes automáticos daquela parte.

| Fase | Tema | Estado |
| --- | --- | --- |
| 1 | base | concluída |
| 2 | memória e CPU | concluída |
| 3 | objetos e executive | concluída |
| 4 | I/O e armazenamento | concluída |
| 5 | Registro e serviços | concluída |
| 6 | loader PE e ntoskrnl | em andamento |
| 7 | modo usuário | em andamento |
| 8 | vídeo, arquivos e rede | planejada |

**Marco atual.** O NtUserInitialize do csrss.exe real volta com sucesso: o dxgkrnl.sys inicia o BasicDisplay.sys pela sessão do win32k e o InitVideo da sessão 0 monta a configuração de exibição sobre o dispositivo desconectado do win32k.

**Próximo.** O csrss terminar a inicialização (falta a porta LPC de servidor em modo usuário, o NtCreatePort da \Windows\SbApiPort) para o smss da sessão executar o wininit.exe, que cria a WinSta0 com as Desktops Winlogon e Default (WINSTA0_OK).

Hoje: **43 de 65** binários da Microsoft rodam (20 parciais); o kernel exporta **2.048 dos 3.070** nomes do `ntoskrnl.exe` do Windows 10 22H2 (66,7%). Detalhes em [O que roda](site/o-que-roda.html), [Componentes](site/componentes.html), [Exports](site/ntoskrnl.html) e [Testes](site/testes.html).

## Fase 1 — base (concluída)

Boot pela BIOS até o modo de 64 bits, HAL, nanokernel (interrupções, canais de mensagens, serviços), relógio, escalonador cooperativo, sistema de arquivos em memória, vídeo, console, teclado, shell e a ferramenta de build e testes (cargo xtask).

| Componente | Estado | Teste automático |
| --- | --- | --- |
| Boot em 64 bits | Funciona | entrada, boot |
| Interrupções e timer | Funciona | boot, selftest |
| Vídeo VGA em modo texto | Funciona | boot |
| Teclado PS/2 | Funciona | shell |
| Arquivos em memória | Funciona | selftest, fase3 |
| Shell | Parcial | shell |
| Programas hello e pisca | Funciona | selftest, shell |

## Fase 2 — memória e CPU (concluída)

Banco de páginas físicas, mapeamento recursivo, pool do kernel, variáveis exportadas, imagens carregadas, KUSER_SHARED_DATA, KPCR, IRQL, DPCs, multiprocessador, ACPI, estruturas do NT e acesso à memória de convidado.

| Componente | Estado | Teste automático |
| --- | --- | --- |
| Gerência de memória | Funciona | selftest |
| Multiprocessador (SMP) | Funciona | selftest, fase7 |

## Fase 3 — objetos e executive (concluída)

Object Manager (tipos, handles, namespace, callbacks), biblioteca de runtime, Executive (locks, rundown, listas lookaside, callbacks), segurança (SIDs, ACLs, descritores, tokens) e processos e threads com as estruturas reais do NT.

| Componente | Estado | Teste automático |
| --- | --- | --- |
| Processos e threads | Funciona | selftest, fase3, fase7 |
| Sincronização e despacho | Funciona | fase3, fase7, selftest |
| Gerenciador de objetos e namespace | Parcial | fase3 |
| Segurança e tokens | Parcial | fase3, fase6, fase7 |

## Fase 4 — I/O e armazenamento (concluída)

I/O Manager, ACPI e PCI, gerência de energia, ETW, drivers de barramento, disco ATA e NTFS.

| Componente | Estado | Teste automático |
| --- | --- | --- |
| I/O Manager | Parcial | fase4, teclado, pipes |
| Console | Parcial | boot, shell, condrv |
| Barramento PCI | Parcial | fase4, storage, basicdisplay |
| Dispositivos da placa-mãe | Parcial | fase4 |
| Disco ATA (interno) | Parcial | fase4 |
| NTFS (leitor do kernel) | Parcial | fase4 |

## Fase 5 — Registro e serviços (concluída)

Configuration Manager (hives, chaves e valores) e o controle de serviços e drivers (sc).

| Componente | Estado | Teste automático |
| --- | --- | --- |
| Registro | Parcial | fase5 |
| sc (controle de serviços) | Parcial | fase7 |

## Fase 6 — loader PE e ntoskrnl (em andamento)

Carregador de PE, funções exportadas pelo kernel, Code Integrity real (ci.dll), carga dos drivers reais do Windows (i8042prt, kbdclass, mouclass, cng.sys, watchdog.sys), o runtime KMDF (WdfLdr.sys e Wdf01000.sys) e o ksecdd.sys.

| Componente | Estado | Teste automático |
| --- | --- | --- |
| Depurador do kernel | Funciona | kd |
| Carregador de PE e exports do kernel | Parcial | fase6, boot |
| hal.dll | Funciona | drivers |
| i8042prt.sys | Funciona | teclado, drivers, shell, bugcheck |
| kbdclass.sys | Funciona | teclado, drivers, shell |
| mouclass.sys | Funciona | drivers, teclado |
| wmilib.sys e WppRecorder.sys | Funciona | teclado, drivers |
| atapi.sys e ataport.sys | Parcial | drivers |
| disk.sys e classpnp.sys | Parcial | drivers |
| mountmgr.sys | Parcial | drivers |
| cng.sys | Funciona | drivers |
| ci.dll (Code Integrity) | Funciona | watchdog |
| watchdog.sys | Funciona | watchdog |
| KMDF (WdfLdr.sys e Wdf01000.sys) | Funciona | kmdf, basicdisplay |
| ksecdd.sys | Funciona | ksecdd |
| null.sys | Funciona | null |
| beep.sys | Funciona | beep |
| fs_rec.sys | Funciona | fs_rec |
| ksecpkg.sys | Funciona | ksecpkg |
| ahcache.sys, ws2ifsl.sys, bowser.sys e afunix.sys | Funciona | drivers-software |

## Fase 7 — modo usuário (em andamento)

Processos e threads de usuário, comunicação ALPC, chamadas de sistema, as bibliotecas ntdll e KERNEL32 reais e o csrss.exe real.

| Componente | Estado | Teste automático |
| --- | --- | --- |
| Jobs | Funciona | fase7 |
| npfs.sys | Funciona | pipes, drivers, smss-csrss |
| msfs.sys | Funciona | pipes, drivers, smss-csrss |
| Modo usuário | Parcial | fase7 |
| ntdll.dll, KERNEL32 e KERNELBASE | Planejado | — |
| Executáveis .exe (comando exec) | Planejado | — |
| csrss.exe | Parcial | — |

## Fase 8 — vídeo, arquivos e rede (planejada)

Cache Manager e os drivers reais do Windows para a tela gráfica (win32k.sys, dxgkrnl.sys, BasicDisplay.sys), os sistemas de arquivos (ntfs.sys, fastfat.sys, fltmgr.sys) e a rede (ndis.sys, tcpip.sys, E1G6032E.sys), com o kernel dando só o suporte.

| Componente | Estado | Teste automático |
| --- | --- | --- |
| Cache Manager | Parcial | fase6, ntfs |
| win32k.sys, win32kbase.sys e win32kfull.sys | Parcial | win32k, win32k-display |
| acpi.sys e pci.sys | Parcial | acpi |
| dxgkrnl.sys e BasicDisplay.sys | Parcial | dxgkrnl, basicdisplay, win32k-display, fase6 |
| ntfs.sys, fastfat.sys e fltmgr.sys | Parcial | ntfs |
| ndis.sys, tcpip.sys e E1G6032E.sys | Parcial | ndis, afd, tcpip |
