//! Binários reais do Windows desta máquina, copiados no build (nunca ficam
//! no repositório).
//!
//! O hal.dll, as pilhas de teclado/mouse e de armazenamento e as bibliotecas
//! de export que elas importam (wmilib.sys e WppRecorder.sys) entram no
//! bundle do kernel (a fase 0 os copia para o sistema de arquivos em
//! memória), com o MUI da biblioteca de recursos de boot (bootres.dll.mui,
//! os textos da tela de bugcheck no idioma de boot da instalação). A tabela
//! de mensagens do ntoskrnl.exe (os nomes dos códigos de bugcheck) vai para
//! a seção de recursos do PE do kernel. O volume NTFS leva o cng.sys, a cadeia da CI (ci.dll, msrpc.sys
//! e a lista de revogação), os file systems de pipes e mailslots (npfs.sys e
//! msfs.sys), o runtime do KMDF com um cliente (WdfLdr.sys, Wdf01000.sys,
//! SleepStudyHelper.sys e msisadrv.sys) e os catálogos que os assinam, a
//! raiz ACPI da árvore de dispositivos (acpi.sys, pci.sys e a pshed.dll), o
//! banco de errata (`\SystemRoot\INF\errata.inf`), a
//! pilha de vídeo (dxgkrnl.sys, dxgmms2.sys e o BasicDisplay.sys do
//! repositório de drivers), os
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
//! subsistema Win32 (win32k.sys, win32kbase.sys, win32kfull.sys, com o
//! hidparse.sys e o cdd.dll).

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
    // A pilha IDE e de volumes que o PnP sobe com `--storage=real`.
    "System32/drivers/intelide.sys",
    "System32/drivers/pciidex.sys",
    "System32/drivers/partmgr.sys",
    "System32/drivers/volmgr.sys",
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
    // O powrprof.dll dos imports de energia do winlogon (api-ms-win-power-*)
    // e o imm32.dll que o user32 carrega ao inicializar.
    "powrprof.dll",
    "imm32.dll",
];

/// As imagens de kernel do caminho do smss (`--initial-process=smss`): o
/// win32k.sys que o smss da sessão carrega pela classe 38, o win32kbase.sys
/// e o win32kfull.sys que ele carrega como imagens de sessão, o hidparse.sys
/// que vem antes do win32kfull e o cdd.dll (o driver de exibição do GDI).
/// (caminho no volume, origem no Windows).
const SMSS_KERNEL_IMAGES: &[(&str, &str)] = &[
    ("WIN32K.SYS", "System32/win32k.sys"),
    ("WIN32KBASE.SYS", "System32/win32kbase.sys"),
    ("WIN32KFULL.SYS", "System32/win32kfull.sys"),
    ("HIDPARSE.SYS", "System32/drivers/hidparse.sys"),
    ("CDD.DLL", "System32/cdd.dll"),
];

fn windows_directory() -> PathBuf {
    std::env::var("SystemRoot").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("C:/Windows"))
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
    candidates.into_iter().next()
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
        for name in SMSS_PROGRAMS {
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
        println!("programas de modo usuario do smss no volume NTFS: {staged} de {}", SMSS_PROGRAMS.len());
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
    }
    files.push((String::from("NTOSKRNL.EXE"), kernel_pe.to_vec()));
    files.push((String::from("Windows/System32/ntoskrnl.exe"), kernel_pe.to_vec()));
    Ok(files)
}
