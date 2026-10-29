# OpenNT

**一个自由的 NT 操作系统，专注于兼容 Windows 10 及更高版本，包括这些版本的设备驱动程序。**

OpenNT 开发 NT 内核、系统服务、Win32 环境以及现代应用程序和驱动程序需要的接口。AMD64（x86-64）是主要开发平台，项目也保留了上游的 ARM64、RISC-V64 和其他架构移植。

Windows 10+ 驱动兼容性是开发目标，并不表示所有驱动程序目前都能运行。每个驱动都需要结合目标 Windows 版本和实际硬件进行测试。在 QEMU 中成功启动不能证明真实硬件驱动的兼容性。

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
