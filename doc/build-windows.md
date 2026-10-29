# Build OpenNT on Windows

The AMD64 image can be built directly on Windows with RosBE and MSYS2. This route does not use WSL.

## Tools

- Git for Windows and Python 3.
- The Windows x64 package from the upstream [RosBE releases](https://github.com/LiberNT/libernt-build-toolchain/releases). The package provides the target LLVM compiler, Windows-host `llvm-mingw` compilers, CMake, Ninja, Flex/Bison and QEMU.
- [MSYS2](https://www.msys2.org/) for the NTFS image tool's POSIX dependencies.

Install the host packages in an MSYS2 shell:

```sh
pacman -S --needed gcc cmake ninja
```

Install the Python generator dependencies in the Python environment used by the build:

```bat
python -m pip install mako packaging PyYAML
```

## Build the NTFS image tool

From an MSYS2 shell, enter your OpenNT checkout and run:

```sh
cmake -S sdk/tools/ntfsimg/host -B output-Clang-amd64-debug/host-tools/ntfs -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build output-Clang-amd64-debug/host-tools/ntfs --parallel 4
```

The executable is `output-Clang-amd64-debug/host-tools/ntfs/ntfsimg.exe`. Its MSYS2 runtime DLLs must be available when native Windows CMake runs it.

## Configure the OS

Before configuring, fetch the Mesa source feed from Git Bash in the checkout with `./scripts/feeds update mesa`.

Open `cmd.exe` in the checkout. Set the following paths to your actual installations; the RosBE package's versioned directory names may differ:

```bat
set "ROSBE_ROOT=C:\Tools\rosbe"
set "MSYS2_ROOT=C:\msys64"
set "CCACHE_DISABLE=1"
set "PATH=%ROSBE_ROOT%\llvm\bin;%ROSBE_ROOT%\llvm-mingw\bin;%ROSBE_ROOT%\cmake-3.31.6\bin;%ROSBE_ROOT%\ninja-1.12.1;%ROSBE_ROOT%\win_flex_bison-2.5.25;%SystemRoot%\System32;%SystemRoot%;%MSYS2_ROOT%\usr\bin;%PATH%"
call configure.cmd /clang /arch=amd64 -DENABLE_CCACHE=OFF -DDIAGDATA_CHANNEL= -DHOST_TOOLS_C_COMPILER:FILEPATH=%ROSBE_ROOT%/llvm-mingw/bin/clang.exe -DHOST_TOOLS_CXX_COMPILER:FILEPATH=%ROSBE_ROOT%/llvm-mingw/bin/clang++.exe -DHOST_NTFSIMG:FILEPATH=%CD%/output-Clang-amd64-debug/host-tools/ntfs/ntfsimg.exe
```

The target compiler comes from `llvm/bin`. The host compilers come from `llvm-mingw/bin`, because build helpers must run on Windows. Keep Windows `System32` before Unix tools on `PATH`: `configure.cmd` uses Windows `find`.

Ensure the same Python installation can import `mako`, `packaging` and `yaml` before configuring.

## Build and run

```bat
ninja -C output-Clang-amd64-debug -j 12 openntimg
"%ROSBE_ROOT%\qemu-11.1.0\qemu-system-x86_64.exe" -name OpenNT -machine pc -accel whpx -m 4096 -smp 4 -drive file=output-Clang-amd64-debug/OpenNT.img,format=raw,if=ide -vga std -usb -device usb-tablet -nic user,model=e1000 -display sdl
```

Use `-accel tcg` if Windows Hypervisor Platform is unavailable. Shut down QEMU before regenerating `OpenNT.img`; a rebuild replaces the guest disk's contents.

Keep `-usb -device usb-tablet` enabled for absolute pointer coordinates and reliable window dragging. The reusable `scripts\run-qemu.cmd` launcher includes this configuration.

The local Windows validation uses the AMD64 build with WoW64, a 1 GiB raw disk, 4 GiB guest RAM and four virtual CPUs. Other target architectures require their own validation.
