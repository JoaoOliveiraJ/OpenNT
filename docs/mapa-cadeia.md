# Mapa da cadeia de modo usuário até a tela de logon

Este mapa lista o que falta para a cadeia real do Windows sair do ponto
onde para hoje e chegar à tela de logon. Ele foi montado por análise
estática dos binários desta máquina (Windows 10 19041), antes de qualquer
boot. O objetivo é corrigir os bloqueios em paralelo.

**Para o PIXEL3 e os ajudantes:** a lista completa, uma linha por item,
está no TSV `mapa.tsv` gerado pela ferramenta (seção "Ferramenta"). As
seções 3 a 6 abaixo trazem só os itens de prioridade A e os de núcleo.

## 1. Onde a cadeia está

- smss → csrss → wininit (WinSta0) → winlogon na sessão 1 → lsass →
  services.exe (`SERVICES_STARTED`).
- O próximo passo é o início automático do services.exe: os grupos do
  svchost (DcomLaunch, RPCSS e os outros) e os serviços de processo
  próprio.
- Depois: o LSM liga o `Global\TermSrvReadyEvent` e conecta a sessão 1
  (csrss → NtUserRemoteConnect → dxgkrnl → cdd.dll); o winlogon sobe o
  LogonUI.exe; o dwm.exe sobe com D3D11, DXGI, WARP e DirectComposition.

## 2. Método

Estágios e binários de partida:

| Estágio | Binários de partida |
|---|---|
| 1-servicos | services.exe, svchost.exe e o ServiceDll (ou o executável) de cada serviço Win32 com Start=2, sem início atrasado, desta máquina |
| 2-lsm-sessao | lsm.dll, winsta.dll, wmsgapi.dll, sysntfy.dll, csrss.exe, winsrv.dll, winsrvext.dll; no kernel: win32k*.sys, cdd.dll, dxgkrnl.sys, dxgmms2.sys, BasicDisplay.sys, BasicRender.sys, monitor.sys |
| 3-logonui | winlogon.exe, LogonUI.exe, LogonController.dll, Windows.UI.Logon.dll, authui.dll, dui70.dll, duser.dll, uxtheme.dll e os provedores de credencial habilitados no registro |
| 4-dwm | dwm.exe, dwminit.dll, dwmcore.dll, uDWM.dll, dwmredir.dll, dwmghost.dll, d3d11, dxgi, d3d10warp, dcomp, d2d1, dwrite, CoreMessaging, CoreUIComponents, WindowsCodecs, D3DSCache |

Para cada estágio:

- **Fecho "req":** imports estáticos, com os API sets resolvidos pelo
  apisetschema.dll desta máquina. Sem eles a imagem não carrega.
- **Fecho "atr":** imports de carga atrasada do fecho req, mais o fecho
  estático deles. Só carregam quando a função é chamada.
- **Binário específico:** um binário de partida ou uma DLL que ainda não
  está no volume de boot. O resto é infraestrutura (kernelbase, rpcrt4,
  combase...).
- **Prioridade A:** usado por um binário específico do fecho req.
  **B:** binário específico do fecho atr, ou syscall alcançada dentro da
  ntdll a partir de uma função que um binário específico importa.
  **C:** só a infraestrutura usa.
- **Núcleo (estágio 1):** usado pelos binários dos grupos DcomLaunch e
  RPCSS (svchost.exe, rpcss.dll, RpcEpMap.dll, umpo.dll, psmsrv.dll,
  SystemEventsBrokerServer.dll).

Cada categoria foi conferida contra o OpenNT:

- **Syscalls:** imports Nt*/Zw* da ntdll e as syscalls que as funções
  Rtl*/Etw*/Tp* importadas alcançam dentro da ntdll (até 4 chamadas). Uma
  syscall conta como atendida só se tem handler de modo usuário
  registrado (`state::register_handler`); o export de kernel sozinho não
  atende o modo usuário (`ex/system_services.rs`).
- **Chaves:** strings com caminho de registro (`SYSTEM\...`,
  `SOFTWARE\...`, `\Registry\Machine\...`), comparadas com as hives que o
  xtask grava e com as chaves que o kernel cria em tempo de execução. Só
  entram as chaves que existem nesta máquina.
- **Arquivos:** membros dos fechos e nomes de DLL/EXE em strings,
  comparados com o que `xtask/src/windows_binaries.rs` põe no volume.
- **Objetos nomeados:** `\RPC Control\`, `\BaseNamedObjects\`, `Global\`,
  `Local\`, `\Device\`, pipes, `\\.\nome` e os diretórios do kernel.
- **Drivers:** imports do ntoskrnl sem export no OpenNT, para os drivers
  da cadeia e os que eles importam.

Os itens que o PIXEL3 e os ajudantes já fizeram nos branches deles
aparecem com estado `pixel3`.

## 3. Estágio 1: services.exe e svchost

Números (só o que falta): syscalls A 28, B 55, C 63 (10 no núcleo);
chaves A 294, B 204, C 94 (20 no núcleo); arquivos A 57, B 161 (4 no
núcleo); objetos A 56, B 31, C 11; drivers fora do volume ou com imports
sem export: 19.

Serviços automáticos desta máquina (Start=2, sem atraso, Microsoft): 46.
Os atrasados (CDPSvc, DispBrokerDesktopSvc, DoSvc, MapsBroker, StorSvc,
UsoSvc, wscsvc, sppsvc, WSearch) começam cerca de 2 minutos depois e não
bloqueiam a tela de logon. Os de terceiros desta máquina ficam fora.

### 3.1 Núcleo (DcomLaunch e RPCSS)

| Item | Usado por | Tipo |
|---|---|---|
| NtCompareTokens | rpcss.dll, usermgr.dll | feito |
| NtSetUuidSeed | RpcEpMap.dll | feito |
| NtAccessCheckByType | psmsrv.dll | simples sobre o `se/access_check.rs` do PIXEL3 |
| NtCreateIRTimer, NtSetIRTimer | umpo.dll | simples sobre o ETIMER do PIXEL3 |
| NtDeleteWnfStateName, NtDeleteWnfStateData, NtQueryWnfStateNameInformation, NtUnsubscribeWnfStateChange | psmsrv, services, RpcEpMap, schedsvc e quase toda DLL de serviço | simples (WNF, com o pixel3-gaps) |
| NtPowerInformation de modo usuário | services, umpo, psmsrv, schedsvc... | simples (pixel3-gaps) |
| `SOFTWARE\Microsoft\OLE`, `COM3`, `Rpc`, `Rpc\Extensions` | rpcss, RpcEpMap | feito |
| `SOFTWARE\Microsoft\WindowsRuntime\AllowedCOMCLSIDs`, `Windows NT\CurrentVersion\Containers`, `NetworkServiceTriggers` | rpcss, RpcEpMap | feito |
| `SYSTEM\CurrentControlSet\Control\Power` (1065 chaves) | umpo.dll | simples, só quando o serviço Power entrar |
| `Services\SystemEventsBroker\Parameters`, `BackgroundModel\Brokers` | SystemEventsBrokerServer, brokerlib | simples, junto com o serviço |
| umpo.dll, psmsrv.dll, SystemEventsBrokerServer.dll, brokerlib.dll | Power, BrokerInfrastructure, SystemEventsBroker | feito |
| chaves de serviço Power, BrokerInfrastructure e SystemEventsBroker | services.exe | simples, mas muda o que o início automático sobe no svchost do LSM: decisão do pixel3-scm |

### 3.2 Resto do estágio 1 (prioridade A)

- **Syscalls simples:** NtCompareObjects (feito),
  NtIsSystemResumeAutomatic (feito), NtFilterToken,
  NtQueryOpenSubKeysEx (feito), NtSetVolumeInformationFile, NtLoadDriver e
  NtUnloadDriver de modo usuário (o export existe), NtSetIoCompletionEx,
  NtAllocateReserveObject (export existe), NtDeleteFile (export existe).
- **Syscalls complexas:** NtSetThreadExecutionState (pedido de energia
  por thread: PopCreateUserPowerRequest e as flags legadas),
  NtAllocateUuids (número de sequência persistido em
  `RtlGetPersistedStateLocation`), NtEnumerateBootEntries,
  NtQueryBootEntryOrder, NtQueryBootOptions e
  NtSetSystemEnvironmentValue (variáveis de firmware), NtLoadKey3,
  NtTranslateFilePath, NtAcquireProcessActivityReference, as transações
  do KTM e do registro (NtCreateTransaction, NtCommitTransaction,
  NtCreateKeyTransacted e os vizinhos, prioridade B).
- **Chaves:** 294 de prioridade A, quase todas lidas por um único
  serviço (audio, firewall, rede, agendador, perfis). Cada uma é cópia
  simples desta máquina; a lista está no TSV.
- **Objetos de kernel:** `\\.\WMIDataDevice` (criado pelo WMI do
  ntoskrnl, ausente no OpenNT; complexo), `\Device\Afd`, `\Device\Tcp`,
  `\Device\Udp`, `\Device\RawIp` (drivers já no volume, precisam iniciar).
- **Drivers fora do volume:** nsiproxy.sys (o serviço nsi depende dele,
  0 imports sem export: simples), rdpdr.sys, wanarp.sys, mpsdrv.sys,
  ndiswan.sys, bam.sys (0 imports sem export: simples). Com imports sem
  export: mup.sys (7), dfsc.sys (3), mmcss.sys (3), rdyboost.sys (1),
  msquic.sys (3), http.sys (12), mrxsmb.sys (10), rdbss.sys (14),
  srvnet.sys (17), srv2.sys (22). Os da rede SMB só importam para
  LanmanServer e LanmanWorkstation, que não bloqueiam o logon.

## 4. Estágio 2: LSM e conexão da sessão

Números: syscalls A 2, B 15; chaves A 7, B 169; arquivos B 39; objetos
A 2, B 22; drivers fora do volume: 4.

| Item | Usado por | Tipo |
|---|---|---|
| NtOpenSession, NtNotifyChangeSession | lsm.dll | em andamento no pixel3-lsm |
| NtPowerInformation, NtQueryWnfStateNameInformation | winsrvext.dll | pixel3-gaps |
| `Control\Terminal Server` e subchaves | lsm.dll, winlogon | em andamento no pixel3-lsm |
| `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` (valores) | lsm.dll, winlogon | simples (feito: `service_chain.rs`, sem os valores do usuário desta máquina) |
| `SYSTEM\Setup` e `Setup\Status` | lsm.dll | feito |
| `SOFTWARE\Microsoft\Windows\CurrentVersion\SharedPC` | lsm.dll | feito |
| `Control\PriorityControl` | winsrvext.dll | feito |
| `\KernelObjects\SystemErrorPortReady` | winsrvext.dll | médio: evento de notificação do DbgkpInitializePhase1SiloState, com descritor próprio (World, LocalSystem, Local, AllAppPackages e um SID de capacidade) |
| `\SmSsWinStationApiPort` | lsm.dll, winsrvext.dll | criado pelo smss.exe real; verificar no boot |
| BasicRender.sys, monitor.sys, cea.sys | dxgkrnl (adaptador de renderização e monitor) | arquivos simples; o dispositivo ROOT\BasicRender e o filho de monitor precisam do PnP: complexo |
| werkernel.sys | watchdog.sys, win32kbase.sys | fora de propósito: o API set fica com host vazio (`mm/sysload.rs`) |

Os imports de kernel do win32k.sys, win32kbase.sys, win32kfull.sys,
cdd.dll, dxgkrnl.sys, dxgmms2.sys, BasicDisplay.sys, BasicRender.sys e
monitor.sys estão todos atendidos (0 sem export).

Quem chama o NtUserRemoteConnect (com o NtUserRemoteRedrawScreen, o
NtUserRemoteStopScreenUpdates e o NtUserCtxDisplayIOCtl) é o
winsrvext.dll do csrss, pelo win32u.dll.

As chamadas gráficas de modo usuário (NtUser*, NtGdi*, NtDxgk* e
NtGdiDdDDI*) vão para o win32k real pela tabela de serviço 1. O
D3DKMT* do gdi32 é encaminhado para o win32u, e os NtGdiDdDDI* do
win32k chegam ao dxgkrnl pelo API set
`ext-ms-win-core-win32k-dxgk` (205 funções). Não há syscall gráfica a
implementar no OpenNT; o que falta é o dxgkrnl ter adaptador
(BasicDisplay e BasicRender iniciados pelo PnP) quando o csrss conectar
a sessão.

## 5. Estágio 3: LogonUI

Números: syscalls B 2; chaves A 68, B 71; arquivos A 24, B 59;
objetos A 1.

- **Syscalls:** NtFlushInstallUILanguage (winlogon, pelo
  RtlpVerifyAndCommitUILanguageSettings; simples), NtFlushProcessWriteBuffers
  (d3d11; simples: IPI de barreira em todas as CPUs do processo).
- **Arquivos (todos simples):** LogonUI.exe, LogonController.dll,
  Windows.UI.Logon.dll, authui.dll, dui70.dll, duser.dll, uxtheme.dll,
  wincorlib.dll, credprovs.dll, credprovslegacy.dll e os provedores de
  credencial habilitados (biocredprov, certcredprovider, cngcredui,
  cxcredprov, FaceCredentialProvider, fidocredprov, ngccredprov,
  RdpCredentialProvider, SmartcardCredentialProvider,
  TrustedSignalCredProv, wlidcredprov) com aadauthhelper, cryptngc e
  ngckeyenum.
- **Chaves (simples):** `Authentication\Credential Providers` e
  `Authentication\LogonUI\*`, `Control\Winlogon` e `Notifications`,
  `Control\Keyboard Layouts` e `Control\Nls\Locale` (a hive do OpenNT
  não tem as duas), `Accessibility`, `OOBE\*`, `Lock Screen`,
  `Themes\DefaultColors`, `Cryptography\Ngc` e `PwdlessPlat`,
  `Services\TPM`, `WinBio`.
- **Complexo:** o LogonUI ativa classes COM e WinRT (Windows.UI.Logon,
  XAML, CoreMessaging). Isso exige as registrações em
  `SOFTWARE\Classes\CLSID`, `AppID`, `Interface` e
  `SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId`, que a análise
  de strings não enxerga (os CLSIDs são GUIDs binários). É o maior bloco
  de trabalho deste estágio.

## 6. Estágio 4: DWM

Números: arquivos A 8, B 30; chaves A 1, B 13; objetos B 8. Nenhuma
syscall nova da ntdll.

- **Arquivos (simples):** dwm.exe, dwmcore.dll, uDWM.dll, dwmredir.dll,
  dwmghost.dll, d3d10warp.dll, D3DCompiler_47.dll, D3DSCache.dll.
- **Chave:** `SOFTWARE\Microsoft\Windows\CurrentVersion\PerceptionSimulationExtensions`
  (uDWM).
- **Complexo:** o caminho D3D11 → DXGI → D3DKMT precisa de um adaptador
  de renderização no dxgkrnl. Com WARP, o adaptador é o Microsoft Basic
  Render Driver (BasicRender.sys, raiz `ROOT\BasicRender`), cujo driver
  de modo usuário (d3d10warp.dll) vem do valor `UserModeDriverName` da
  chave da classe de vídeo
  `Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\NNNN`. O OpenNT
  ainda não instala esse dispositivo.

## 7. Defeito encontrado

As `UpperFilters` das classes de teclado e mouse ficam em
`SYSTEM\Control\Class\{...}` (raiz da hive), e não em
`SYSTEM\ControlSet001\Control\Class\{...}`: a semente em
`cm/service/boot_services.rs` não tem o prefixo `CurrentControlSet`, e o
`io/pnp/mod.rs` lê o mesmo caminho fora do conjunto de controle. Os dois
lados batem entre si, mas qualquer binário real (cfgmgr32, setupapi, o
próprio PnP do Windows) procura em `CurrentControlSet\Control\Class`.

## 8. Ferramenta

Os scripts ficam no scratchpad da sessão, na pasta `mapa`:

- `mapa.py <worktree> <worktree do PIXEL3> <saída>`: gera `mapa.tsv`
  (colunas estagio, prioridade, nucleo, categoria, item, usado_por,
  estado, dificuldade, nota) e `mapa.json` (fechos por estágio).
- `pelib.py`: API sets, imports, strings e o alcance das exportações da
  ntdll até os stubs de syscall.
- `regf.py`: leitor das hives que o xtask grava.
- `services_probe.py`: serviços desta máquina com ImagePath, ServiceDll
  e dependências.

As hives do OpenNT para a comparação saem de
`hive_image::machine_hives(true)`. A leitura de algumas chaves desta
máquina exige administrador (por exemplo `Services\nsi\Parameters`); o
xtask copia só o que a conta de build consegue ler.

## 9. Itens simples já feitos

- Syscalls de modo usuário com a semântica do 19041 e autoteste
  (`test/user_service_chain.rs`): NtCompareObjects
  (`ob/compare_objects.rs`), NtCompareTokens (`se/token/compare.rs`),
  NtSetUuidSeed (`ex/uuid.rs`) e NtIsSystemResumeAutomatic
  (`po/system_state.rs`).
- Chaves copiadas desta máquina (`xtask/src/service_chain.rs`): OLE, COM3,
  Rpc, WindowsRuntime\AllowedCOMCLSIDs, CurrentVersion\Containers,
  NetworkServiceTriggers, SharedPC, os valores do Winlogon (sem os do
  usuário desta máquina), SYSTEM\Setup (só o estado do setup),
  Setup\Status e Control\PriorityControl.
- Arquivos no volume: umpo.dll, psmsrv.dll, SystemEventsBrokerServer.dll e
  brokerlib.dll.
