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

**Marco atual.** Na sessão 0, o wininit.exe real cria o services.exe e o lsass.exe reais. O lsass instala o banco de política e o banco de contas de um sistema novo, inicializa a auditoria, as sessões de logon, as credenciais e os pacotes de segurança e publica as interfaces RPC do LSA; o services.exe consulta o domínio da conta no lsass, publica a interface RPC do gerenciador de serviços e cria os svchost dos grupos DcomLaunch e rpcss com o token do logon de serviço; sobem o Power, o DcomLaunch, o RpcEptMapper e o RpcSs, e o Local Session Manager sobe no svchost do DcomLaunch e sinaliza o TermSrvReadyEvent. Na sessão 1, o winlogon.exe real registra o processo de logon pelo RPC de kernel do msrpc.sys, abre as Desktops Winlogon, Disconnect e Default da WinSta0 dele e chama o SwitchDesktop; o InitVideo da sessão carrega o cdd.dll sobre o adaptador de renderização do BasicRender.sys e o win32k desenha o ponteiro do mouse na tela pelo BasicDisplay.sys (o primeiro pixel). O LSM conecta a sessão 1 ao console pelo csrss dela, e o winlogon carrega o tema e cria o dwm.exe e o LogonUI.exe reais.

**Próximo.** O dwm.exe e o LogonUI.exe seguirem até a tela de logon: o dwm compõe sobre o adaptador WARP do BasicRender a interface XAML que o LogonUI mostra.

Hoje: **56 de 85** binários da Microsoft rodam (28 parciais); o kernel exporta **2.155 dos 3.070** nomes do `ntoskrnl.exe` do Windows 10 22H2 (70,2%). Detalhes em [O que roda](site/o-que-roda.html), [Componentes](site/componentes.html), [Exports](site/ntoskrnl.html) e [Testes](site/testes.html).

## Fase 1 — base (concluída)

Boot pela BIOS até o modo de 64 bits, HAL, nanokernel (interrupções, canais de mensagens, serviços), relógio, escalonador cooperativo, sistema de arquivos em memória, vídeo, console, teclado, shell e a ferramenta de build e testes (cargo xtask).

| Componente | Estado | Teste automático |
| --- | --- | --- |
| Boot em 64 bits | Funciona | entrada, boot |
| Interrupções e timer | Funciona | boot, selftest |
| Vídeo VGA em modo texto | Funciona | boot |
| Teclado PS/2 | Funciona | shell |
| Arquivos em memória | Funciona | selftest, fase3 |
| Shell | Parcial | shell, shell-shutdown |
| Programas hello e pisca | Funciona | selftest, shell |

## Fase 2 — memória e CPU (concluída)

Banco de páginas físicas, mapeamento recursivo, pool do kernel, variáveis exportadas, imagens carregadas, KUSER_SHARED_DATA, KPCR, IRQL, DPCs, multiprocessador, ACPI, estruturas do NT e acesso à memória de convidado.

| Componente | Estado | Teste automático |
| --- | --- | --- |
| Gerência de memória | Funciona | selftest, pagefile |
| Multiprocessador (SMP) | Funciona | selftest, fase7, logonui-smp2, area-de-trabalho-smp2, barra-de-tarefas-smp2 |
| Estado estendido do processador (XSAVE e AVX) | Funciona | xstate, selftest |

## Fase 3 — objetos e executive (concluída)

Object Manager (tipos, handles, namespace, callbacks), biblioteca de runtime, Executive (locks, rundown, listas lookaside, callbacks), segurança (SIDs, ACLs, descritores, tokens) e processos e threads com as estruturas reais do NT.

| Componente | Estado | Teste automático |
| --- | --- | --- |
| Processos e threads | Funciona | selftest, fase3, fase6, fase7 |
| Sincronização e despacho | Funciona | fase3, fase7, selftest |
| Gerenciador de objetos e namespace | Parcial | fase3 |
| Segurança e tokens | Parcial | fase3, fase6, fase7 |

## Fase 4 — I/O e armazenamento (concluída)

I/O Manager, ACPI e PCI, gerência de energia, ETW, drivers de barramento, disco ATA e NTFS.

| Componente | Estado | Teste automático |
| --- | --- | --- |
| I/O Manager | Parcial | fase4, teclado, pipes |
| Desligamento e reinício | Funciona | shutdown, reboot, shell-shutdown |
| Console | Parcial | boot, shell, condrv |
| Barramento PCI | Parcial | fase4, storage, basicdisplay, usb |
| Dispositivos da placa-mãe | Parcial | fase4 |
| Disco ATA (interno) | Parcial | fase4, ata-falha |
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
| Depurador do kernel | Funciona | kd, kd-parada, kd-usuario, kd-smp2, kd-usuario-smp2, reinicio-do-shell |
| Relógio e fuso horário | Funciona | relogio, selftest, fase6, fase7 |
| Carregador de PE e exports do kernel | Parcial | fase6, boot |
| hal.dll | Funciona | drivers |
| i8042prt.sys | Funciona | teclado, drivers, shell, bugcheck, teclado-e-mouse |
| kbdclass.sys | Funciona | teclado, drivers, shell, teclado-e-mouse |
| mouclass.sys | Funciona | drivers, teclado, teclado-e-mouse |
| wmilib.sys e WppRecorder.sys | Funciona | teclado, drivers |
| atapi.sys e ataport.sys | Parcial | drivers |
| disk.sys e classpnp.sys | Parcial | drivers |
| mountmgr.sys | Parcial | drivers, nvme |
| cng.sys | Funciona | drivers |
| ci.dll (Code Integrity) | Funciona | watchdog |
| watchdog.sys | Funciona | watchdog |
| KMDF (WdfLdr.sys e Wdf01000.sys) | Funciona | kmdf, basicdisplay, usb |
| ksecdd.sys | Funciona | ksecdd |
| null.sys | Funciona | null |
| beep.sys | Funciona | beep |
| fs_rec.sys | Funciona | fs_rec |
| ksecpkg.sys | Funciona | ksecpkg |
| ahcache.sys, ws2ifsl.sys, bowser.sys e afunix.sys | Funciona | drivers-software |
| mup.sys, dfsc.sys, udfs.sys e cldflt.sys | Funciona | drivers-arquivos-rede |

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
| Cache Manager | Parcial | fase6, ntfs, nvme, e-process |
| win32k.sys, win32kbase.sys e win32kfull.sys | Parcial | win32k, win32k-display, reinicio-do-shell |
| acpi.sys e pci.sys | Parcial | acpi, usb |
| Pilha USB 3 e HID (usbxhci.sys, ucx01000.sys, usbhub3.sys, hidusb.sys, hidclass.sys, kbdhid.sys e mouhid.sys) | Parcial | usb |
| dxgkrnl.sys e BasicDisplay.sys | Parcial | dxgkrnl, basicdisplay, win32k-display, fase6 |
| ntfs.sys, fastfat.sys e fltmgr.sys | Parcial | ntfs, shutdown, reboot, minifilters, nvme |
| ndis.sys, tcpip.sys e E1G6032E.sys | Parcial | ndis, afd, tcpip, rede |
