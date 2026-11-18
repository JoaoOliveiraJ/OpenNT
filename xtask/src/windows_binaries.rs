//! Binários reais do Windows desta máquina, copiados no build (nunca ficam
//! no repositório).
//!
//! O hal.dll, as pilhas de teclado/mouse e de armazenamento e as bibliotecas
//! de export que elas importam (wmilib.sys e WppRecorder.sys) entram no
//! bundle do kernel (a fase 0 os copia para o sistema de arquivos em
//! memória), com o hwpolicy.sys (a política do XSAVE, lida no boot), o MUI da biblioteca de recursos de boot (bootres.dll.mui,
//! os textos da tela de bugcheck no idioma de boot da instalação). A tabela
//! de mensagens do ntoskrnl.exe (os nomes dos códigos de bugcheck) vai para
//! a seção de recursos do PE do kernel. O volume NTFS leva o cng.sys, a cadeia da CI (ci.dll, msrpc.sys
//! e a lista de revogação), os file systems de pipes e mailslots (npfs.sys e
//! msfs.sys), o runtime do KMDF com um cliente (WdfLdr.sys, Wdf01000.sys,
//! SleepStudyHelper.sys e msisadrv.sys) e os catálogos que os assinam, a
//! raiz ACPI da árvore de dispositivos (acpi.sys, pci.sys e a pshed.dll), o
//! banco de errata (`\SystemRoot\INF\errata.inf`), a
//! pilha de vídeo (dxgkrnl.sys, dxgmms2.sys, o BasicDisplay.sys e o
//! BasicRender.sys do repositório de drivers e o monitor.sys com o CEA.sys
//! e o monitor.inf), a pilha USB 3 e HID (usbxhci.sys, ucx01000.sys,
//! usbhub3.sys, usbd.sys, hidusb.sys, hidclass.sys, hidparse.sys, kbdhid.sys
//! e mouhid.sys), o miniport da placa e1000 (E1G6032E.sys, do repositório de
//! drivers), o TPM 2.0 (tpm.sys e tbs.sys), os
//! arquivos que o vgk.sys abre pelo caminho
//! completo, o PE do kernel e o próprio vgk.sys quando houver um: um
//! `vgk.sys` na raiz do repositório ou o caminho em `OPENNT_VGK_SYS`.
//!
//! Com `--initial-process=smss`, o volume leva também os programas de modo
//! usuário que o smss.exe real e o csrss.exe real carregam, na raiz (o
//! `C:\Windows\System32` que o modo usuário vê): os dois executáveis, as
//! DLLs de servidor do csrss e o fecho dos imports delas (estáticos e pelos
//! API sets do apisetschema.dll desta máquina), o wininit.exe da sessão 0
//! com o services.exe e o lsass.exe que ele cria, e as imagens de kernel do
//! subsistema Win32 (win32k.sys, win32kbase.sys, win32kfull.sys e o
//! cdd.dll; o hidparse.sys que o win32kbase importa já vem com a pilha USB).
//! Leva também a tela de logon da sessão 1 (o dwm.exe e o LogonUI.exe com o
//! fecho dos imports, o XAML e os provedores de credencial), os `.mui` dos
//! programas (no idioma de fallback quando o de interface não tem), os
//! recursos deles em `\Windows\SystemResources`, os assemblies de WinSxS
//! (`side_by_side`), as fontes (`fonts`), o tema visual (`theme`) e as
//! pastas de dados que a tela de logon lê (os metadados WinRT, as imagens da tela de bloqueio e as do
//! bloco do usuário, e os dados do ICU e dos fusos de `\Windows\Globalization`).

use std::fs;
use std::path::{Path, PathBuf};

/// Imagens do bundle, relativas ao diretório do Windows.
const BUNDLED: &[&str] = &[
    "System32/hal.dll",
    "System32/drivers/kbdclass.sys",
    "System32/drivers/i8042prt.sys",
    "System32/drivers/mouclass.sys",
    "System32/drivers/ataport.sys",
    "System32/drivers/atapi.sys",
    "System32/drivers/disk.sys",
    "System32/drivers/classpnp.sys",
    "System32/drivers/mountmgr.sys",
    "System32/drivers/wmilib.sys",
    "System32/drivers/WppRecorder.sys",
    "System32/drivers/watchdog.sys",
    // O driver de política de hardware: a política do XSAVE (o recurso 0x65)
    // que o KiInitializeXSave consulta.
    "System32/drivers/hwpolicy.sys",
    // A pilha IDE e de volumes que o PnP sobe com `--storage=real`, e o
    // volume.sys, o driver de função do devnode STORAGE\Volume que o
    // volmgr.sys relata (volume.inf).
    "System32/drivers/intelide.sys",
    "System32/drivers/pciidex.sys",
    "System32/drivers/partmgr.sys",
    "System32/drivers/volmgr.sys",
    "System32/drivers/volume.sys",
];

/// Arquivos do volume NTFS: (caminho no volume, origem no Windows).
const NTFS_FILES: &[(&str, &str)] = &[
    ("CNG.SYS", "System32/drivers/cng.sys"),
    // O núcleo gráfico (DXGKrnl), iniciado por `--start-driver=DXGKrnl`, e o
    // gerenciador de memória de vídeo que ele carrega quando um adaptador
    // inicia.
    ("DXGKRNL.SYS", "System32/drivers/dxgkrnl.sys"),
    ("DXGMMS2.SYS", "System32/drivers/dxgmms2.sys"),
    // O driver de vídeo básico (`--display=basic`), no repositório de drivers
    // onde a instalação o deixa (o ImagePath do serviço BasicDisplay).
    (
        "Windows/System32/DriverStore/FileRepository/basicdisplay.inf_amd64_19e58b6267591a82/BasicDisplay.sys",
        "System32/DriverStore/FileRepository/basicdisplay.inf_amd64_19e58b6267591a82/BasicDisplay.sys",
    ),
    // O driver de renderização básico (o adaptador WARP do dxgkrnl, na
    // instância ROOT\BasicRender da raiz), também no repositório de drivers
    // (o ImagePath do serviço BasicRender); os catálogos 0110 e 0516 abaixo o
    // cobrem.
    (
        "Windows/System32/DriverStore/FileRepository/basicrender.inf_amd64_eebb5a8467eb88ec/BasicRender.sys",
        "System32/DriverStore/FileRepository/basicrender.inf_amd64_eebb5a8467eb88ec/BasicRender.sys",
    ),
    // O driver de função dos monitores que o dxgkrnl relata no adaptador
    // (monitor.inf), um cliente KMDF, com o CEA.sys que ele importa (sobre o
    // msrpc.sys) e o INF; o catálogo 01 cobre o monitor.sys, e o 0516 e o
    // 05110 abaixo, o CEA.sys.
    ("MONITOR.SYS", "System32/drivers/monitor.sys"),
    ("CEA.SYS", "System32/drivers/CEA.sys"),
    ("Windows/INF/monitor.inf", "INF/monitor.inf"),
    (
        "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package01~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
        "System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package01~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
    ),
    // A CI original e a sua dependência, carregadas do volume.
    ("CI.DLL", "System32/ci.dll"),
    ("MSRPC.SYS", "System32/drivers/msrpc.sys"),
    // Provedor dos contadores de desempenho (driver de boot) e o console, a
    // segurança do kernel e a pilha de rede (com as bibliotecas de export
    // que importam), iniciados sob demanda (`--start-driver`).
    ("PCW.SYS", "System32/drivers/pcw.sys"),
    ("CONDRV.SYS", "System32/drivers/condrv.sys"),
    ("KSECDD.SYS", "System32/drivers/ksecdd.sys"),
    ("NETIO.SYS", "System32/drivers/netio.sys"),
    ("NDIS.SYS", "System32/drivers/ndis.sys"),
    ("TCPIP.SYS", "System32/drivers/tcpip.sys"),
    ("AFD.SYS", "System32/drivers/afd.sys"),
    ("FWPKCLNT.SYS", "System32/drivers/fwpkclnt.sys"),
    ("TDI.SYS", "System32/drivers/tdi.sys"),
    ("FLTMGR.SYS", "System32/drivers/fltmgr.sys"),
    // O pacote de segurança do KSecDD, o \Device\Null, o \Device\Beep e os
    // reconhecedores de file system, iniciados sob demanda (`--start-driver`).
    ("KSECPKG.SYS", "System32/drivers/ksecpkg.sys"),
    ("NULL.SYS", "System32/drivers/null.sys"),
    ("BEEP.SYS", "System32/drivers/beep.sys"),
    ("FS_REC.SYS", "System32/drivers/fs_rec.sys"),
    // Imagem real carregada em duas sessões pelo autoteste do espaço de
    // sessão (MmLoadSystemImage com MM_LOAD_IMAGE_IN_SESSION): só importa do
    // ntoskrnl e tem uma seção .data gravável.
    ("BOOTVID.DLL", "System32/BOOTVID.DLL"),
    // Os file systems de pipes nomeados e mailslots: serviços de sistema
    // (Start 1, grupo "File system") que todo boot carrega.
    ("NPFS.SYS", "System32/drivers/npfs.sys"),
    ("MSFS.SYS", "System32/drivers/msfs.sys"),
    // Esquema de API sets: os imports ext-ms-* das imagens de kernel.
    ("APISETSCHEMA.DLL", "System32/apisetschema.dll"),
    // A CI lê a lista de revogação pelo caminho completo.
    ("Windows/System32/CodeIntegrity/driver.stl", "System32/CodeIntegrity/driver.stl"),
    // Catálogo de assinatura da Microsoft que cobre o watchdog.sys e o
    // dxgkrnl.sys (drivers inbox são assinados por catálogo, não embutido): a
    // ci.dll varre \SystemRoot\System32\CatRoot\{GUID}\*.cat e valida o hash da
    // imagem contra ele. O catálogo encadeia na Microsoft Root CA 2010, que a
    // ci.dll já conhece (a mesma raiz que valida o vgk.sys).
    (
        "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0510~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
        "System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0510~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
    ),
    // O ntfs.sys real (`--start-driver=ntfs`); o catálogo 0516 abaixo o
    // cobre, e também o null.sys, o fs_rec.sys, o ksecpkg.sys, o clfs.sys e
    // o fltmgr.sys.
    ("NTFS.SYS", "System32/drivers/ntfs.sys"),
    // KMDF: a WdfLdr.sys (biblioteca de import dos clientes), o runtime
    // Wdf01000.sys (carregado pela WdfLdr pela chave do serviço) e a
    // SleepStudyHelper.sys que ele importa; o msisadrv.sys é um cliente KMDF.
    // Os catálogos da Microsoft que os assinam: o 0516 (o mesmo do ntfs.sys)
    // assina a WdfLdr, o Wdf01000, a SleepStudyHelper e a WppRecorder; o
    // 0110, o msisadrv.
    ("WDFLDR.SYS", "System32/drivers/WdfLdr.sys"),
    ("WDF01000.SYS", "System32/drivers/Wdf01000.sys"),
    ("SLEEPSTUDYHELPER.SYS", "System32/drivers/SleepStudyHelper.sys"),
    ("MSISADRV.SYS", "System32/drivers/msisadrv.sys"),
    // A raiz ACPI da árvore de dispositivos (`--pnp-root=acpi`): o acpi.sys
    // no dispositivo ACPI da HAL, o pci.sys no barramento PCI que ele
    // enumera e a pshed.dll que o pci.sys importa.
    ("ACPI.SYS", "System32/drivers/acpi.sys"),
    ("PCI.SYS", "System32/drivers/pci.sys"),
    ("PSHED.DLL", "System32/pshed.dll"),
    // A pilha USB 3 e HID (`--usb`): o driver da controladora xHCI com a
    // extensão de classe UCX (biblioteca de classe do KMDF, carregada pela
    // WdfLdr), o hub USB 3 com a biblioteca USBD, o minidriver HID de USB
    // com a classe HID e o interpretador de relatórios, e os drivers HID de
    // teclado e mouse (o kbdclass e o mouclass vêm do bundle).
    ("USBXHCI.SYS", "System32/drivers/USBXHCI.SYS"),
    ("UCX01000.SYS", "System32/drivers/Ucx01000.sys"),
    ("USBHUB3.SYS", "System32/drivers/USBHUB3.SYS"),
    ("USBD.SYS", "System32/drivers/usbd.sys"),
    ("HIDUSB.SYS", "System32/drivers/hidusb.sys"),
    ("HIDCLASS.SYS", "System32/drivers/hidclass.sys"),
    ("HIDPARSE.SYS", "System32/drivers/hidparse.sys"),
    ("KBDHID.SYS", "System32/drivers/kbdhid.sys"),
    ("MOUHID.SYS", "System32/drivers/mouhid.sys"),
    // O banco do Errata Manager: o carregador entrega a imagem do
    // \SystemRoot\INF\errata.inf ao kernel, que a interpreta no boot.
    ("Windows/INF/errata.inf", "INF/errata.inf"),
    (
        "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0516~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
        "System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0516~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
    ),
    // Catálogo que cobre o beep.sys.
    (
        "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0517~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
        "System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0517~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
    ),
    (
        "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0110~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
        "System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0110~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
    ),
    // O catálogo que cobre a pilha PS/2 do bundle (i8042prt.sys, kbdclass.sys
    // e mouclass.sys, achado pelo hash da imagem no CatRoot desta máquina):
    // num boot com a CI ativa (`--start-driver`), a pilha de teclado passa
    // pela validação depois do driver iniciado.
    (
        "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0511~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
        "System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0511~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
    ),
    // Os módulos que os file systems importam: o clfs.sys (pelo
    // ext-ms-win-fs-clfs, só o ntfs.sys) e o clipsp.sys (pelo
    // ext-ms-win-ntos-clipsp), com o catálogo próprio do clipsp.sys.
    ("CLFS.SYS", "System32/drivers/clfs.sys"),
    ("CLIPSP.SYS", "System32/drivers/clipsp.sys"),
    (
        "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Shared-814DB60DB621E2916AD769AF5F228BED19224212D92876A292990439227807A6~31bf3856ad364e35~amd64~~10.0.19041.7664.cat",
        "System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Shared-814DB60DB621E2916AD769AF5F228BED19224212D92876A292990439227807A6~31bf3856ad364e35~amd64~~10.0.19041.7664.cat",
    ),
    // Os minifiltros de file system que o FltMgr hospeda sobre o volume do
    // ntfs.sys (`--start-driver=FileInfo,...`); os catálogos 0511 e 0516
    // acima cobrem o bindflt.sys, o wcifs.sys e o storqosflt.sys, o 0515
    // cobre o FileInfo.sys, o Wof.sys e o CldFlt.sys, e o 0519, o luafv.sys.
    ("FILEINFO.SYS", "System32/drivers/FileInfo.sys"),
    ("WOF.SYS", "System32/drivers/Wof.sys"),
    ("STORQOSFLT.SYS", "System32/drivers/storqosflt.sys"),
    ("BINDFLT.SYS", "System32/drivers/bindflt.sys"),
    ("WCIFS.SYS", "System32/drivers/wcifs.sys"),
    ("LUAFV.SYS", "System32/drivers/luafv.sys"),
    ("CLDFLT.SYS", "System32/drivers/CldFlt.sys"),
    (
        "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0515~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
        "System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0515~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
    ),
    (
        "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0519~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
        "System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0519~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
    ),
    // A pilha NVMe que o PnP sobe com `--storage=nvme`: o miniport
    // stornvme.sys e o driver de porta storport.sys, que ele importa.
    ("STORPORT.SYS", "System32/drivers/storport.sys"),
    ("STORNVME.SYS", "System32/drivers/stornvme.sys"),
    // O miniport Intel PRO/1000 que o PnP instala na placa e1000 com
    // `--net` (nete1g3e.inf): o `[e1000.CopyFiles]` o copia para o
    // System32\drivers (%12%), o ImagePath do serviço E1G60; nesta máquina
    // ele só está no repositório de drivers. O catálogo 0110 acima o cobre.
    ("E1G6032E.SYS", "System32/DriverStore/FileRepository/nete1g3e.inf_amd64_af58b4e19562a3f9/E1G6032E.sys"),
    // O TPM 2.0 do `--tpm`: o tpm.sys, que o PnP instala no ACPI\MSFT0101
    // pelo tpm.inf, e o tbs.sys, a API de TPM de kernel que manda comandos a
    // ele.
    ("TPM.SYS", "System32/drivers/tpm.sys"),
    ("TBS.SYS", "System32/drivers/tbs.sys"),
    // O fastfat.sys real (`--start-driver=fastfat`) e o catálogo que o cobre.
    ("FASTFAT.SYS", "System32/drivers/fastfat.sys"),
    (
        "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
        "System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
    ),
    // Drivers de software sem hardware (`--start-driver`), cujos imports do
    // ntoskrnl já têm export: o cache de compatibilidade de aplicativos
    // (ahcache), o IFS do Winsock 2 (ws2ifsl), o navegador de rede (bowser)
    // e os sockets AF_UNIX (afunix, sobre o NETIO.SYS), com os catálogos
    // que os cobrem (0519, 05110, 04 e 05112).
    ("AHCACHE.SYS", "System32/drivers/ahcache.sys"),
    ("WS2IFSL.SYS", "System32/drivers/ws2ifsl.sys"),
    ("BOWSER.SYS", "System32/drivers/bowser.sys"),
    ("AFUNIX.SYS", "System32/drivers/afunix.sys"),
    (
        "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0519~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
        "System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0519~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
    ),
    (
        "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package05112~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
        "System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package05112~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
    ),
    (
        "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package05110~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
        "System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package05110~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
    ),
    (
        "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package04~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
        "System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package04~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
    ),
    // Mais drivers de software sem hardware (`--start-driver`): o
    // redirecionador UNC (mup) com o cliente DFS (dfsc, que importa o
    // mup.sys) e o file system UDF (udfs). O catálogo 0516 cobre o mup.sys
    // e o dfsc.sys, e o Client-Features 0317, o udfs.sys.
    ("MUP.SYS", "System32/drivers/mup.sys"),
    ("DFSC.SYS", "System32/drivers/dfsc.sys"),
    ("UDFS.SYS", "System32/drivers/udfs.sys"),
    (
        "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Features-Package0317~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
        "System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Features-Package0317~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
    ),
    // Abertos pelo vgk.sys pelo caminho SystemRoot.
    ("Windows/System32/ntdll.dll", "System32/ntdll.dll"),
    ("Windows/System32/win32k.sys", "System32/win32k.sys"),
    ("Windows/System32/drivers/fltmgr.sys", "System32/drivers/fltmgr.sys"),
];

/// Os programas de modo usuário do caminho do smss (`--initial-process=smss`):
/// smss.exe, csrss.exe, as DLLs de servidor (csrsrv, basesrv, winsrv com o
/// winsrvext, sxssrv) e o fecho dos imports delas, incluindo a ntdll, e o
/// wininit.exe com o services.exe e o lsass.exe.
const SMSS_PROGRAMS: &[&str] = &[
    "smss.exe",
    "csrss.exe",
    "csrsrv.dll",
    "basesrv.dll",
    "winsrv.dll",
    "winsrvext.dll",
    "sxssrv.dll",
    "sxs.dll",
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "user32.dll",
    "win32u.dll",
    "gdi32.dll",
    "gdi32full.dll",
    "msvcp_win.dll",
    "ucrtbase.dll",
    "combase.dll",
    "rpcrt4.dll",
    "cfgmgr32.dll",
    // O comando inicial da sessão 0 (wininit.exe, que o smss da sessão
    // executa depois do csrss) e os processos que ele cria: o gerenciador de
    // serviços (services.exe) e a autoridade de segurança local (lsass.exe,
    // que carrega o lsasrv.dll). Os imports estáticos deles e as DLLs que
    // eles carregam na partida (o advapi32 e o winsta das estações de
    // janela, o wininitext, o userenv, o sspicli e as dependências do
    // lsasrv).
    "wininit.exe",
    "wininitext.dll",
    "services.exe",
    "lsass.exe",
    "lsasrv.dll",
    "sechost.dll",
    "advapi32.dll",
    "winsta.dll",
    "userenv.dll",
    "profapi.dll",
    "bcrypt.dll",
    "bcryptprimitives.dll",
    "cryptbase.dll",
    "sspicli.dll",
    "devobj.dll",
    "dpapi.dll",
    "eventaggregation.dll",
    "msasn1.dll",
    "wldap32.dll",
    "ws2_32.dll",
    "msvcrt.dll",
    // O que o wininit carrega na partida (o kernel.appcore das APIs de
    // aplicativo e o dwminit da inicialização do DWM), o comando inicial da
    // sessão 1 (winlogon.exe) e as DLLs de carga atrasada que o services.exe
    // e o lsass.exe usam ao iniciar (o servidor SSPI, o SAM, a criptografia
    // e a rede local).
    "kernel.appcore.dll",
    "dwminit.dll",
    "winlogon.exe",
    "sspisrv.dll",
    "samsrv.dll",
    "samlib.dll",
    "authz.dll",
    "crypt32.dll",
    "cryptsp.dll",
    "cryptdll.dll",
    "ncrypt.dll",
    "netutils.dll",
    "srvcli.dll",
    "wintrust.dll",
    "nsi.dll",
    "iphlpapi.dll",
    "dnsapi.dll",
    // O powrprof.dll dos imports de energia do winlogon (api-ms-win-power-*),
    // o imm32.dll que o user32 carrega ao inicializar e o kbdus.dll, o
    // layout de teclado que o CreateWindowStationW do user32 abre para o
    // NtUserCreateWindowStation.
    "powrprof.dll",
    "imm32.dll",
    "kbdus.dll",
    // A cadeia do Local Session Manager que o services.exe inicia
    // (`user_services`): o svchost.exe, os ServiceDll do DcomLaunch e do
    // RpcSs (rpcss.dll), do RpcEptMapper (RpcEpMap.dll) e do LSM (lsm.dll),
    // e o dwmapi.dll que o lsm.dll importa.
    "svchost.exe",
    "rpcss.dll",
    "rpcepmap.dll",
    "lsm.dll",
    "dwmapi.dll",
    // As cargas atrasadas do lsm.dll no caminho de subida: o sysntfy.dll
    // (SysNotifyStartServer do CWinlogonNotify), o WMsgAPI.dll
    // (WmsgSendMessage, os avisos de sessão ao winlogon) e o usermgrcli.dll
    // (CamIsCandidateUser do CSessionArbitrationDefault::Initialize).
    "sysntfy.dll",
    "wmsgapi.dll",
    "usermgrcli.dll",
    // As extensões do LSA que o lsass.exe carrega (o efslsaext.dll e o
    // dpapisrv.dll, com o ntasn1.dll e o shcore.dll que eles importam).
    "efslsaext.dll",
    "dpapisrv.dll",
    "ntasn1.dll",
    "shcore.dll",
    // O servidor da configuração de segurança que o services.exe carrega
    // (ext-ms-win-scesrv-server) e o pacote de notificação dele no lsass.
    "scesrv.dll",
    "scecli.dll",
    // O pacote de autenticação do LSA (Control\Lsa, Authentication
    // Packages) que atende o LogonUserExExW dos serviços.
    "msv1_0.dll",
    "ntlmshared.dll",
    // O wldp.dll (a política de bloqueio do Windows, carga atrasada do
    // lsasrv no LsapCheckIfMachineIsSecureByDefault), com o oleaut32.dll que
    // ele importa, e o umpdc.dll, importado pelo powrprof.dll.
    "wldp.dll",
    "oleaut32.dll",
    "umpdc.dll",
    // Os nomes de exibição dos privilégios, que o LsapDbInitializePrivilegeObject
    // do lsasrv carrega ao montar o banco de política, e o ole32.dll que o
    // wldp.dll carrega.
    "msprivs.dll",
    "ole32.dll",
    // Os pacotes de segurança que o LoadPackages do lsasrv carrega (o
    // negoexts.dll e o kerberos.dll) e o netlogon.dll que o samsrv.dll
    // carrega, com o logoncli.dll e o gmsaclient.dll que ele importa.
    "negoexts.dll",
    "kerberos.dll",
    "netlogon.dll",
    "logoncli.dll",
    "gmsaclient.dll",
    // As cargas atrasadas do kerberos.dll e do LSA que um sistema sem elas
    // transforma em exceção (VcppException ERROR_MOD_NOT_FOUND) no
    // SpmpBootPackage: o kerbclientshared.dll, o winhttp.dll, o
    // httpprxc.dll e o netprovfw.dll; e o secur32.dll, o dsparse.dll, o
    // samcli.dll e o laps.dll do lsasrv, do samsrv e do netlogon.
    "kerbclientshared.dll",
    "winhttp.dll",
    "httpprxc.dll",
    "netprovfw.dll",
    "secur32.dll",
    "dsparse.dll",
    "samcli.dll",
    "laps.dll",
    // E as cargas atrasadas desses: o joinutil.dll e o winbrand.dll do
    // netprovfw.dll, e o webio.dll, o websocket.dll, o dhcpcsvc.dll, o
    // ondemandconnroutehelper.dll e o firewallapi.dll do winhttp.dll e do
    // kerberos.dll.
    "joinutil.dll",
    "winbrand.dll",
    "webio.dll",
    "websocket.dll",
    "dhcpcsvc.dll",
    "ondemandconnroutehelper.dll",
    "firewallapi.dll",
    // Os outros pacotes de segurança da lista interna do lsasrv (o
    // wdigest.dll, o tspkg.dll, o schannel.dll, o pku2u.dll e o cloudap.dll,
    // com o ntmarta.dll que ele importa).
    "wdigest.dll",
    "tspkg.dll",
    "schannel.dll",
    "pku2u.dll",
    "cloudap.dll",
    "ntmarta.dll",
    // O dsrole.dll que o scecli.dll do lsass carrega.
    "dsrole.dll",
    // O WUDFPlatform.dll do gerenciador de drivers de modo usuário que o
    // InitWudfDriverManager do services.exe inicializa antes do início
    // automático; sem ele o SvcctrlMain sai.
    "WUDFPlatform.dll",
    // O umpo.dll do serviço Power carrega o slc.dll (com o sppc.dll) e o
    // umpoext.dll (com o dxgi.dll e o tdh.dll); o winlogon.exe cria o
    // fontdrvhost.exe, o anfitrião das fontes de modo usuário.
    "slc.dll",
    "sppc.dll",
    "umpoext.dll",
    "dxgi.dll",
    "tdh.dll",
    "fontdrvhost.exe",
    // As DLLs de carga adiada dos serviços do svchost: o psmsrv.dll
    // (psmserviceexthost.dll, bisrv.dll, resourcepolicyclient.dll,
    // CSystemEventsBrokerClient.dll e licensemanagerapi.dll), o
    // SystemEventsBrokerServer.dll (DAB.dll), o rpcss.dll (clbcatq.dll,
    // windows.staterepositorycore.dll, capauthz.dll, msiltcfg.dll e
    // version.dll) e o RpcEpMap.dll (rpcrtremote.dll); o DABAPI.dll do
    // services.exe, o rsaenh.dll (o CSP do lsass) e o KDCPW.DLL do samsrv.
    "psmserviceexthost.dll",
    "bisrv.dll",
    "resourcepolicyclient.dll",
    "CSystemEventsBrokerClient.dll",
    "licensemanagerapi.dll",
    "DAB.dll",
    "clbcatq.dll",
    "windows.staterepositorycore.dll",
    "capauthz.dll",
    "msiltcfg.dll",
    "version.dll",
    "rpcrtremote.dll",
    "DABAPI.dll",
    "rsaenh.dll",
    "KDCPW.DLL",
    // O gpapi.dll que o umpoext.dll do serviço Power carrega pelo nome, e o
    // policymanager.dll (com o msvcp110_win.dll), carga adiada do umpo.dll.
    "gpapi.dll",
    "policymanager.dll",
    "msvcp110_win.dll",
];

/// Os outros serviços do grupo DcomLaunch do svchost (o mesmo processo do
/// LSM), pelo mapa da cadeia (`docs/mapa-cadeia.md`): o umpo.dll do serviço
/// Power, o psmsrv.dll do BrokerInfrastructure e o
/// SystemEventsBrokerServer.dll do SystemEventsBroker, com o brokerlib.dll
/// que ele importa, e o umpnpmgr.dll do PlugPlay. Os imports estáticos deles
/// já estão no volume.
const SERVICE_CHAIN_PROGRAMS: &[&str] = &["umpo.dll", "psmsrv.dll", "SystemEventsBrokerServer.dll", "brokerlib.dll", "umpnpmgr.dll"];

/// A tela de logon da sessão 1: o dwm.exe que o dwminit.dll do winlogon
/// cria e o LogonUI.exe do StartLogonUI, com o fecho dos imports estáticos
/// deles (pelos API sets desta máquina) e as cargas sob demanda do caminho
/// até o primeiro quadro.
const LOGON_SCREEN_PROGRAMS: &[&str] = &[
    // O compositor: o dwm.exe com o uDWM.dll e o dwmredir.dll, o motor
    // dwmcore.dll e o que ele importa (D2D, D3D11, o compilador de shaders,
    // a DirectComposition, o CoreMessaging, o CoreUIComponents e o
    // wintypes.dll); o d3d10warp.dll, o driver de modo usuário do WARP que o
    // D3D11 usa no adaptador de renderização básico; e as cargas atrasadas da
    // partida: o dwmghost.dll (DWMGhostInitialize), o avrt.dll do dwmredir,
    // o d3dscache.dll e o dxcore.dll do d3d11.dll, o DWrite.dll com o
    // TextShaping.dll, o WindowsCodecs.dll e o rometadata.dll do wintypes.dll.
    "dwm.exe",
    "uDWM.dll",
    "dwmredir.dll",
    "dwmcore.dll",
    "dwmghost.dll",
    "d2d1.dll",
    "d3d11.dll",
    "d3d10warp.dll",
    "D3DCOMPILER_47.dll",
    "D3DSCache.dll",
    "dxcore.dll",
    "dcomp.dll",
    "CoreMessaging.dll",
    "CoreUIComponents.dll",
    "wintypes.dll",
    "avrt.dll",
    "DWrite.dll",
    "TextShaping.dll",
    "WindowsCodecs.dll",
    "rometadata.dll",
    // O que a thread de eventos do DWM cria no
    // CDesktopManager::InitializeComObjects do uDWM.dll, cuja falha encerra
    // a thread antes de sinalizar a partida: o gerenciador de animações e as
    // bibliotecas de transições (CLSID_UIAnimationManager,
    // CLSID_UIAnimationTransitionLibrary e as versões 2 do
    // CAnimationEngine::Initialize, no UIAnimation.dll) e o agente de vídeo
    // da sessão (a classe WinRT DispBrokerDesktop.SessionBrokerInstance do
    // DispBroker.Desktop.dll, com o mscms.dll e o ColorAdapterClient.dll que
    // ele importa, e o DisplayManager do DispBroker.dll que ela ativa antes
    // da instância global do serviço DispBrokerDesktopSvc); as descrições de
    // vídeo do ddisplay.dll que o uDWM.dll e o dwmcore.dll ativam; o
    // anfitrião de entrada do sistema que o CGlobalMit::Run do dwmcore.dll
    // cria antes do NtMITActivateInputProcessing (CreateSystemInputHost do
    // ism.dll, com o hid.dll); e o compilador dos efeitos que o dcomp.dll
    // serializa e o dwmcore.dll compila para os pincéis de efeito
    // (wuceffects.dll).
    "UIAnimation.dll",
    "DispBroker.Desktop.dll",
    "DispBroker.dll",
    "mscms.dll",
    "ColorAdapterClient.dll",
    "ddisplay.dll",
    "ISM.dll",
    "hid.dll",
    "wuceffects.dll",
    // O LogonUI.exe, o controlador logoncontroller.dll (CLSID
    // {0bdc6fc7-83e3-46a4-bfa0-1bc14dbf8b38}) e a experiência de logon
    // Windows.UI.Logon.dll que ele ativa, o authui.dll e os imports deles,
    // com as cargas atrasadas do logoncontroller.dll (os idiomas, o
    // MSCTF.dll e o credui.dll) e o tema do winlogon (o
    // ThemesOnEarlyCreateSession do uxinit.dll, com o UxTheme.dll).
    "LogonUI.exe",
    "logoncontroller.dll",
    "Windows.UI.Logon.dll",
    "authui.dll",
    "wincorlib.dll",
    "wtsapi32.dll",
    "shlwapi.dll",
    "propsys.dll",
    "Bcp47Langs.dll",
    "WinLangdb.dll",
    "MSCTF.dll",
    "credui.dll",
    "uxinit.dll",
    "UxTheme.dll",
    // O imageres.dll que o authui.dll carrega (o bloco do usuário e os
    // ícones da tela): um módulo só de recursos, que ficam no
    // imageres.dll.mun de SystemResources.
    "imageres.dll",
    // O anfitrião dos provedores de credencial que o CredProvDataModel.dll
    // cria pelo CLSID {7a872d34-bc6b-4f83-b199-22e9c0a91ddc}
    // (credprovhost.dll), o shacct.dll das contas de usuário que ele
    // enumera (CLSID_UserAccounts) e o Windows.UI.Immersive.dll da imagem da
    // tela de bloqueio (ILogonUILockScreenImage, a classe WinRT
    // Windows.System.UserProfile.LockScreen) e do repositório de blocos de
    // usuário que o Windows.UI.Logon.dll cria.
    "credprovhost.dll",
    "shacct.dll",
    "Windows.UI.Immersive.dll",
    // As classes dos controles da tela que o Windows.UI.Logon.dll ativa: o
    // ícone e o painel de rede, a entrada de texto e a acessibilidade (o
    // uiautomationcore.dll).
    "Windows.UI.NetworkUXController.dll",
    "NetworkIcon.dll",
    "Windows.UI.Core.TextInput.dll",
    "uiautomationcore.dll",
    // O indicador de idioma de entrada que o Windows.UI.Logon.dll cria
    // (InputSwitch.dll, CLSID {B9BC2A50-43C3-41AA-A086-5DB14E184BAE}, com o
    // wininet.dll que ele importa); as classes WinRT que o XAML ativa para
    // a escala da tela (Windows.Graphics.dll, DisplayInformation) e o pool
    // de threads (threadpoolwinrt.dll); a manipulação direta do ScrollViewer
    // (directmanipulation.dll, com o NInput.dll que ele e o XAML carregam);
    // e os proxies das interfaces da experiência de logon
    // (Windows.Internal.UI.Logon.ProxyStub.dll) e do ActXPrxy.dll
    // (IXAMLHostWindow) para as chamadas entre os apartamentos do XAML e as
    // threads do servidor RPC do logoncontroller.dll.
    "InputSwitch.dll",
    "wininet.dll",
    "Windows.Graphics.dll",
    "threadpoolwinrt.dll",
    "directmanipulation.dll",
    "NInput.dll",
    "Windows.Internal.UI.Logon.ProxyStub.dll",
    "ActXPrxy.dll",
    // O XAML da experiência de logon: as classes WinRT Windows.UI.Xaml.*, o
    // XAMLHostWindow, o Windows.UI.dll, o Windows.Globalization.dll e o
    // modelo de dados dos provedores de credencial (CredProvDataModel.dll),
    // os temas do XAML, o MRT (mrmcorer.dll, os recursos ms-appx dos .pri),
    // e os imports estáticos deles.
    "Windows.UI.Xaml.dll",
    "Windows.UI.Xaml.Controls.dll",
    "Windows.UI.XamlHost.dll",
    "Windows.UI.Xaml.Resources.Common.dll",
    "Windows.UI.Xaml.Resources.19h1.dll",
    "Windows.UI.dll",
    "Windows.Globalization.dll",
    "Windows.Globalization.Fontgroups.dll",
    "CredProvDataModel.dll",
    "iertutil.dll",
    "WindowManagementAPI.dll",
    "TextInputFramework.dll",
    "InputHost.dll",
    "bcp47mrm.dll",
    "twinapi.appcore.dll",
    "MrmCoreR.dll",
    "XmlLite.dll",
    // O ICU que o Windows.Globalization.dll carrega na primeira Calendar (a
    // do relógio da tela de bloqueio, no
    // SecureLockScreenViewModel::_InitializeTimer do Windows.UI.Logon.dll: o
    // TimeZoneCache lista os fusos pelo ucal_openTimeZones), com os dados de
    // `\Windows\Globalization` (`LOGON_SCREEN_FOLDERS`), e o tzres.dll dos
    // nomes dos fusos; o painel de entrada que o XAML registra quando o foco
    // muda (CLSID_FrameworkInputPane do twinapi.dll, no
    // RegisterInputPaneHandler); e o repositório de contas conectadas que o
    // shacct.dll e o credprovslegacy.dll consultam ao enumerar os usuários
    // (IDStore.dll).
    "icu.dll",
    "tzres.dll",
    "twinapi.dll",
    "IDStore.dll",
    // Os provedores de credencial registrados
    // (`Authentication\Credential Providers`) e os imports deles (o
    // msvcp110_win.dll já está em `SMSS_PROGRAMS`).
    "credprovs.dll",
    "credprovslegacy.dll",
    "BioCredProv.dll",
    "certCredProvider.dll",
    "cngcredui.dll",
    "cxcredprov.dll",
    "devicengccredprov.dll",
    "DeviceCredential.dll",
    "FaceCredentialProvider.dll",
    "fidocredprov.dll",
    "mgmtrefreshcredprov.dll",
    "ngccredprov.dll",
    "rdpcredentialprovider.dll",
    "SmartcardCredentialProvider.dll",
    "TrustedSignalCredProv.dll",
    "wlidcredprov.dll",
    "AadAuthHelper.dll",
    "cryptngc.dll",
    "ngckeyenum.dll",
    "dsreg.dll",
    "wkscli.dll",
];

/// As pastas de dados que a tela de logon lê pelo caminho, inteiras: os
/// metadados WinRT de `System32\WinMetadata` (os `.winmd` que o
/// RoGetMetaDataFile do XAML abre para resolver os tipos) e as imagens
/// padrão da tela de bloqueio de `\Windows\Web\Screen` (o img100.jpg e as
/// outras que o Windows.UI.Immersive.dll lista quando o sistema não tem
/// imagem própria em `SystemData`) e os dados de globalização da Calendar do
/// relógio da tela de bloqueio: o `icudtl.dat` e os `.res` de fusos de
/// `\Windows\Globalization\ICU`, que o icu.dll abre pelo diretório do
/// Windows, e o `timezones.xml` de `\Windows\Globalization\Time Zone`, que o
/// TimeZoneCache do Windows.Globalization.dll lê. (pasta no volume, pasta de
/// origem relativa ao diretório do Windows).
const LOGON_SCREEN_FOLDERS: &[(&str, &str)] = &[
    ("WinMetadata", "System32/WinMetadata"),
    ("Web/Screen", "Web/Screen"),
    ("Globalization/ICU", "Globalization/ICU"),
    ("Globalization/Time Zone", "Globalization/Time Zone"),
];

/// As imagens padrão do bloco do usuário de `%ProgramData%\Microsoft\User
/// Account Pictures`, que o repositório de blocos do Windows.UI.Immersive.dll
/// usa para o "Outro usuário" e as contas sem imagem própria; os
/// `<conta>.dat` das contas desta máquina ficam de fora.
const USER_ACCOUNT_PICTURES: &[&str] = &["user.png", "user-32.png", "user-40.png", "user-48.png", "user-192.png", "user.bmp", "guest.png", "guest.bmp"];

/// As imagens de kernel do caminho do smss (`--initial-process=smss`): o
/// win32k.sys que o smss da sessão carrega pela classe 38, o win32kbase.sys
/// e o win32kfull.sys que ele carrega como imagens de sessão e o cdd.dll (o
/// driver de exibição do GDI); o hidparse.sys que vem antes do win32kfull
/// está no volume de todo boot (`NTFS_FILES`).
/// (caminho no volume, origem no Windows).
const SMSS_KERNEL_IMAGES: &[(&str, &str)] = &[
    ("WIN32K.SYS", "System32/win32k.sys"),
    ("WIN32KBASE.SYS", "System32/win32kbase.sys"),
    ("WIN32KFULL.SYS", "System32/win32kfull.sys"),
    ("CDD.DLL", "System32/cdd.dll"),
];

pub fn windows_directory() -> PathBuf {
    std::env::var("SystemRoot").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("C:/Windows"))
}

/// Os programas de modo usuário do boot do smss, na raiz do volume.
pub fn user_programs() -> impl Iterator<Item = &'static str> {
    SMSS_PROGRAMS.iter().chain(SERVICE_CHAIN_PROGRAMS).chain(LOGON_SCREEN_PROGRAMS).copied()
}

/// Os nomes de arquivo de `directory`.
fn entries(directory: &Path) -> Vec<String> {
    fs::read_dir(directory).map(|entries| entries.filter_map(|entry| entry.ok()).filter_map(|entry| entry.file_name().into_string().ok()).collect()).unwrap_or_default()
}

/// Os recursos de `\Windows\SystemResources` dos programas de
/// [`user_programs`]: o `<nome>.mun` e, para um módulo com pasta própria, o
/// `<módulo>.pri` e o `pris\<módulo>.<idioma>.pri` dos idiomas de interface
/// (ou do primeiro idioma de fallback que o tiver). (caminho no volume,
/// arquivo de origem), com os nomes desta máquina.
fn system_resource_files(windows: &Path, languages: &[String], fallbacks: &[String]) -> Vec<(String, PathBuf)> {
    let directory = windows.join("SystemResources");
    let listing = entries(&directory);
    let find = |names: &[String], wanted: &str| names.iter().find(|name| name.eq_ignore_ascii_case(wanted)).cloned();
    let mut files = Vec::new();
    for program in user_programs() {
        if let Some(name) = find(&listing, &format!("{program}.mun")).filter(|name| directory.join(name).is_file()) {
            files.push((format!("SystemResources/{name}"), directory.join(name)));
        }
        let stem = program.rsplit_once('.').map_or(program, |(stem, _)| stem);
        let Some(folder) = find(&listing, stem).filter(|folder| directory.join(folder).is_dir()) else { continue };
        let package = directory.join(&folder);
        let contents = entries(&package);
        if let Some(name) = find(&contents, &format!("{stem}.pri")) {
            files.push((format!("SystemResources/{folder}/{name}"), package.join(name)));
        }
        let Some(pris) = find(&contents, "pris") else { continue };
        let localized = entries(&package.join(&pris));
        let pick = |language: &String| find(&localized, &format!("{stem}.{language}.pri"));
        let mut chosen: Vec<String> = languages.iter().filter_map(pick).collect();
        if chosen.is_empty() {
            chosen.extend(fallbacks.iter().find_map(pick));
        }
        for name in chosen {
            files.push((format!("SystemResources/{folder}/{pris}/{name}"), package.join(&pris).join(name)));
        }
    }
    files
}

/// Mesmo tamanho e mesma data de modificação: a cópia está em dia.
fn up_to_date(source: &Path, copy: &Path) -> bool {
    match (fs::metadata(source), fs::metadata(copy)) {
        (Ok(source), Ok(copy)) => {
            source.len() == copy.len() && matches!((source.modified(), copy.modified()), (Ok(left), Ok(right)) if left == right)
        }
        _ => false,
    }
}

/// Sufixo das cópias em andamento (`<nome>.parcial-<pid>`).
const PARTIAL: &str = ".parcial-";

/// O MUI da biblioteca de recursos de boot (os textos da tela de bugcheck,
/// que o carregador entrega ao kernel): o do idioma de boot desta
/// instalação, a pasta de `Boot\Resources` que tem o arquivo.
fn boot_resources_mui(windows: &Path) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = fs::read_dir(windows.join("Boot/Resources"))
        .ok()?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().join("bootres.dll.mui"))
        .filter(|path| path.is_file())
        .collect();
    candidates.sort();
    // O idioma de interface desta instalação primeiro (`host_language`).
    let languages = crate::host_language::ui_languages();
    let preferred = candidates.iter().position(|path| path.parent().and_then(|folder| folder.file_name()).and_then(|name| name.to_str()).is_some_and(|name| languages.iter().any(|language| language.eq_ignore_ascii_case(name))));
    match preferred {
        Some(index) => Some(candidates.swap_remove(index)),
        None => candidates.into_iter().next(),
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
}

/// Os bytes do recurso [tipo, nome, primeiro idioma] de um PE em arquivo
/// (RVAs convertidas pela tabela de seções).
fn pe_resource(bytes: &[u8], resource_type: u32, name: u32) -> Option<Vec<u8>> {
    let pe = u32_at(bytes, 0x3C)? as usize;
    let sections = u16_at(bytes, pe + 6)? as usize;
    let optional = pe + 24;
    let table = optional + u16_at(bytes, pe + 20)? as usize;
    let to_offset = |rva: u32| -> Option<usize> {
        (0..sections).find_map(|index| {
            let at = table + index * 40;
            let (size, address, raw) = (u32_at(bytes, at + 8)?, u32_at(bytes, at + 12)?, u32_at(bytes, at + 20)?);
            (rva >= address && rva < address + size).then(|| (rva - address + raw) as usize)
        })
    };
    // O diretório de recursos é o terceiro: em +96 + 16 no PE32 e em
    // +112 + 16 no PE32+.
    let directories = if u16_at(bytes, optional)? == 0x10B { optional + 96 } else { optional + 112 };
    let root = to_offset(u32_at(bytes, directories + 16)?)?;
    let child = |directory: usize, identifier: Option<u32>| -> Option<u32> {
        let count = u16_at(bytes, directory + 12)? as usize + u16_at(bytes, directory + 14)? as usize;
        (0..count).find_map(|index| {
            let entry = directory + 16 + index * 8;
            let (id, target) = (u32_at(bytes, entry)?, u32_at(bytes, entry + 4)?);
            (identifier.is_none_or(|wanted| wanted == id)).then_some(target)
        })
    };
    let names = root + (child(root, Some(resource_type))? & 0x7FFF_FFFF) as usize;
    let languages = root + (child(names, Some(name))? & 0x7FFF_FFFF) as usize;
    let data = root + child(languages, None)? as usize;
    let start = to_offset(u32_at(bytes, data)?)?;
    Some(bytes.get(start..start + u32_at(bytes, data + 4)? as usize)?.to_vec())
}

/// A tabela de mensagens do ntoskrnl.exe desta máquina (RT_MESSAGETABLE 1,
/// com os nomes dos códigos de bugcheck que o KeGetBugMessageText devolve),
/// para a seção de recursos do PE do kernel.
pub fn kernel_message_table() -> Option<Vec<u8>> {
    let bytes = fs::read(windows_directory().join("System32/ntoskrnl.exe")).ok()?;
    pe_resource(&bytes, 11, 1)
}

/// Copia as imagens do bundle para `output`; as ausentes ficam de fora com
/// aviso (o kernel registra a ausência ao carregá-las).
///
/// A pasta está no `rerun-if-changed` do build do kernel: uma cópia em dia
/// fica como está e a cópia nova leva a data do original, para que um build
/// sem mudança não recompile o kernel.
pub fn stage(output: &Path) -> Result<usize, String> {
    let windows = windows_directory();
    fs::create_dir_all(output).map_err(|error| format!("{}: {error}", output.display()))?;
    let mut sources: Vec<PathBuf> = BUNDLED.iter().map(|relative| windows.join(relative)).collect();
    // Os textos da tela de bugcheck, no idioma de boot da instalação.
    sources.extend(boot_resources_mui(&windows));
    // Remove cópias de um build anterior que não pertencem mais à lista.
    let names: Vec<&std::ffi::OsStr> = sources.iter().filter_map(|source| source.file_name()).collect();
    if let Ok(entries) = fs::read_dir(output) {
        for entry in entries.filter_map(|entry| entry.ok()) {
            let partial = entry.file_name().to_string_lossy().contains(PARTIAL);
            if !names.contains(&entry.file_name().as_os_str()) && !partial {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    let mut copied = 0;
    for source in &sources {
        let name = source.file_name().unwrap_or_default();
        let copy = output.join(name);
        if !source.exists() {
            println!("AVISO: {} ausente no Windows desta maquina", source.display());
            let _ = fs::remove_file(&copy);
            continue;
        }
        if !up_to_date(source, &copy) {
            // A cópia nasce com outro nome e troca de lugar inteira: outro
            // build que use a mesma pasta nunca embute um arquivo pela metade.
            let partial = output.join(format!("{}{PARTIAL}{}", name.to_string_lossy(), std::process::id()));
            fs::copy(source, &partial).map_err(|error| format!("{}: {error}", source.display()))?;
            let modified = fs::metadata(source).and_then(|metadata| metadata.modified());
            if let Ok(modified) = modified {
                fs::File::options()
                    .write(true)
                    .open(&partial)
                    .and_then(|file| file.set_modified(modified))
                    .map_err(|error| format!("{}: {error}", partial.display()))?;
            }
            if let Err(error) = fs::rename(&partial, &copy) {
                let _ = fs::remove_file(&partial);
                // Outro build pôs a mesma cópia no lugar antes.
                if !up_to_date(source, &copy) {
                    return Err(format!("{}: {error}", copy.display()));
                }
            }
        }
        copied += 1;
    }
    println!("binarios do Windows no bundle: {copied} de {}", sources.len());
    Ok(copied)
}

/// O vgk.sys: `OPENNT_VGK_SYS` ou `vgk.sys` na raiz do repositório.
fn vgk_source(root: &Path) -> Option<PathBuf> {
    std::env::var_os("OPENNT_VGK_SYS").map(PathBuf::from).or_else(|| Some(root.join("vgk.sys"))).filter(|path| path.is_file())
}

/// Arquivos do volume NTFS que existem nesta máquina, mais o PE do kernel
/// gerado (`NTOSKRNL.EXE` e o caminho canônico em System32) e, com
/// `initial_process == "smss"`, os programas de [`SMSS_PROGRAMS`].
pub fn ntfs_files(root: &Path, kernel_pe: &[u8], initial_process: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
    let windows = windows_directory();
    let mut files = Vec::new();
    let mut present = 0;
    for (name, relative) in NTFS_FILES {
        let source = windows.join(relative);
        if !source.exists() {
            println!("AVISO: {} ausente no Windows desta maquina", source.display());
            continue;
        }
        files.push((String::from(*name), fs::read(&source).map_err(|error| format!("{}: {error}", source.display()))?));
        present += 1;
    }
    println!("binarios do Windows no volume NTFS: {present} de {}", NTFS_FILES.len());
    match vgk_source(root) {
        Some(source) => {
            let bytes = fs::read(&source).map_err(|error| format!("{}: {error}", source.display()))?;
            println!("VGK.SYS no volume NTFS ({} bytes)", bytes.len());
            files.push((String::from("VGK.SYS"), bytes));
        }
        None => println!("AVISO: vgk.sys ausente (OPENNT_VGK_SYS ou vgk.sys na raiz) — volume sem o vgk"),
    }
    // Tabelas NLS reais na raiz (codepages, casing e normalização), como o
    // `C:\Windows\System32` que o kernel e a ntdll consultam.
    let system32 = windows.join("System32");
    let named = ["l_intl.nls", "locale.nls", "normnfc.nls", "normnfd.nls", "normnfkc.nls", "normnfkd.nls", "normidna.nls"];
    let mut tables: Vec<(String, PathBuf)> = fs::read_dir(&system32)
        .map(|entries| entries.filter_map(|entry| entry.ok()).map(|entry| entry.path()).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|path| {
            let name = path.file_name()?.to_str()?.to_lowercase();
            let codepage = name.strip_prefix("c_").and_then(|rest| rest.strip_suffix(".nls")).is_some_and(|digits| !digits.is_empty() && digits.chars().all(|character| character.is_ascii_digit()));
            (codepage || named.contains(&name.as_str())).then(|| (name.to_uppercase(), path))
        })
        .collect();
    tables.sort();
    tables.push((String::from("SORTDEFAULT.NLS"), windows.join("Globalization/Sorting/SortDefault.nls")));
    let mut nls = 0;
    for (name, source) in tables {
        if let Ok(bytes) = fs::read(&source) {
            files.push((name, bytes));
            nls += 1;
        }
    }
    println!("tabelas NLS no volume NTFS: {nls}");
    if initial_process == "smss" {
        let mut staged = 0;
        for name in user_programs() {
            let source = system32.join(name);
            match fs::read(&source) {
                Ok(bytes) => {
                    // Na raiz, como o resto de System32 (e de System32\Drivers).
                    files.push((name.rsplit('/').next().unwrap_or(name).to_uppercase(), bytes));
                    staged += 1;
                }
                Err(_) => println!("AVISO: {} ausente no Windows desta maquina", source.display()),
            }
        }
        println!("programas de modo usuario do smss no volume NTFS: {staged} de {}", user_programs().count());
        let mut images = 0;
        for (name, relative) in SMSS_KERNEL_IMAGES {
            let source = windows.join(relative);
            match fs::read(&source) {
                Ok(bytes) => {
                    files.push((String::from(*name), bytes));
                    images += 1;
                }
                Err(_) => println!("AVISO: {} ausente no Windows desta maquina", source.display()),
            }
        }
        println!("imagens de kernel do smss no volume NTFS: {images} de {}", SMSS_KERNEL_IMAGES.len());
        // Os recursos dos programas e das imagens de System32 nos idiomas de
        // interface desta máquina (`System32\<idioma>\<nome>.mui`), que o
        // carregador de recursos procura pelo idioma do convidado (o mesmo
        // daqui, `host_language`), ou no idioma de fallback quando o
        // arquivo não tem `.mui` neles.
        let languages = crate::host_language::ui_languages();
        let fallbacks = crate::host_language::fallback_languages(&languages);
        let names = user_programs().chain(SMSS_KERNEL_IMAGES.iter().filter_map(|(_, relative)| relative.strip_prefix("System32/").filter(|rest| !rest.contains('/'))));
        let mut resources = 0;
        for name in names {
            for (path, source) in crate::host_language::mui_files(&system32, name, &languages, &fallbacks) {
                if let Ok(bytes) = fs::read(&source) {
                    files.push((path, bytes));
                    resources += 1;
                }
            }
        }
        println!("recursos .mui no volume NTFS: {resources} (idiomas {}; fallback {})", languages.join(", "), fallbacks.join(", "));
        // Os módulos de recursos de `\Windows\SystemResources` dos
        // programas: o `<nome>.mun` que o carregador abre no lugar da seção
        // de recursos do módulo e o pacote MRT `<módulo>\<módulo>.pri` (com
        // `pris\<módulo>.<idioma>.pri`) dos componentes WinRT.
        let mut packages = 0;
        for (path, source) in system_resource_files(&windows, &languages, &fallbacks) {
            if let Ok(bytes) = fs::read(&source) {
                files.push((path, bytes));
                packages += 1;
            }
        }
        println!("recursos de SystemResources no volume NTFS: {packages}");
        // Os manifestos dos assemblies lado a lado (o contexto de ativação
        // padrão do sistema e os controles comuns da versão 6, de
        // `side_by_side`) e os arquivos deles, no caminho de WinSxS.
        let mut assemblies = 0;
        for (path, source) in crate::side_by_side::assembly_files(&windows) {
            if let Ok(bytes) = fs::read(&source) {
                files.push((path, bytes));
                assemblies += 1;
            }
        }
        println!("arquivos de WinSxS no volume NTFS: {assemblies}");
        // As fontes da sessão (`fonts`), em `\SystemRoot\Fonts`.
        let mut faces = 0;
        for (path, source) in crate::fonts::files(&windows) {
            match fs::read(&source) {
                Ok(bytes) => {
                    files.push((path, bytes));
                    faces += 1;
                }
                Err(_) => println!("AVISO: {} ausente no Windows desta maquina", source.display()),
            }
        }
        println!("fontes no volume NTFS: {faces}");
        // O tema visual da sessão (`theme`), em
        // `\Windows\Resources\Themes\aero`.
        let mut styles = 0;
        for (path, source) in crate::theme::files(&windows, &languages, &fallbacks) {
            match fs::read(&source) {
                Ok(bytes) => {
                    files.push((path, bytes));
                    styles += 1;
                }
                Err(_) => println!("AVISO: {} ausente no Windows desta maquina", source.display()),
            }
        }
        println!("arquivos do tema no volume NTFS: {styles}");
        // As pastas de dados da tela de logon (`LOGON_SCREEN_FOLDERS`) e as
        // imagens padrão do bloco do usuário (`USER_ACCOUNT_PICTURES`).
        let mut data = 0;
        for (folder, relative) in LOGON_SCREEN_FOLDERS {
            let directory = windows.join(relative);
            let mut names = entries(&directory);
            names.sort();
            for name in names {
                let source = directory.join(&name);
                if !source.is_file() {
                    continue;
                }
                if let Ok(bytes) = fs::read(&source) {
                    files.push((format!("{folder}/{name}"), bytes));
                    data += 1;
                }
            }
        }
        let pictures = std::env::var("ProgramData").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("C:/ProgramData")).join("Microsoft/User Account Pictures");
        for name in USER_ACCOUNT_PICTURES {
            if let Ok(bytes) = fs::read(pictures.join(name)) {
                files.push((format!("ProgramData/Microsoft/User Account Pictures/{name}"), bytes));
                data += 1;
            }
        }
        println!("arquivos das pastas de dados da tela de logon no volume NTFS: {data}");
    }
    files.push((String::from("NTOSKRNL.EXE"), kernel_pe.to_vec()));
    files.push((String::from("Windows/System32/ntoskrnl.exe"), kernel_pe.to_vec()));
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::user_programs;

    /// Cada programa entra uma vez na raiz do volume: um nome repetido em
    /// duas listas daria duas entradas iguais no índice do diretório (e dois
    /// `.mui` e dois recursos de SystemResources).
    #[test]
    fn each_program_is_staged_once() {
        let names: Vec<String> = user_programs().map(str::to_ascii_lowercase).collect();
        for (index, name) in names.iter().enumerate() {
            assert!(!names[..index].contains(name), "{name} aparece em mais de uma lista de programas");
        }
    }
}
