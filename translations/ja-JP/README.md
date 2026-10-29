# OpenNT

**Windows 10 以降のアプリケーションとデバイスドライバーとの互換性を目指す、自由な NT オペレーティングシステムです。**

OpenNT は NT カーネル、システムサービス、Win32 環境、最新のドライバーに必要なインターフェイスを開発します。主な開発対象は AMD64（x86-64）です。上流プロジェクトから継承した ARM64、RISC-V64 などの移植も保持しています。

Windows 10+ ドライバーへの対応は開発目標であり、すべてのドライバーが動作するという意味ではありません。対象の Windows バージョンと実機で、ドライバーごとの検証が必要です。QEMU での起動成功だけでは、実機のドライバー互換性は確認できません。

![OpenNT](../../media/graphics/branding/opennt-banner.svg)

## Build / Compilation

```sh
git clone https://github.com/JoaoOliveiraJ/OpenNT.git
cd OpenNT
./configure.sh -a amd64
ninja -C output-Clang-amd64-debug openntimg
```

- [README / current project status](../../README.md)
- [Native Windows build guide](../../doc/build-windows.md)
- [Installation](../../INSTALL.md)
- [Issues](https://github.com/JoaoOliveiraJ/OpenNT/issues)
- [License](../../COPYING) · [Credits and upstream authors](../../CREDITS.md)

OpenNT is derived from LiberNT and ReactOS. Original copyright notices and component licenses are retained.
