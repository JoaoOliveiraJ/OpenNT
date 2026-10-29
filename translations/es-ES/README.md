# OpenNT

**Un sistema operativo NT libre enfocado en la compatibilidad con Windows 10 y versiones posteriores, incluidos sus controladores.**

OpenNT desarrolla el núcleo, los servicios del sistema, el entorno Win32 y las interfaces necesarias para aplicaciones y controladores modernos. AMD64 (x86-64) es la plataforma principal de desarrollo. El proyecto conserva los puertos heredados para ARM64, RISC-V64 y otras arquitecturas.

El soporte de controladores de Windows 10+ es un objetivo de desarrollo: no significa que todos funcionen ya. Cada controlador requiere pruebas con su hardware y la versión de Windows correspondiente. Arrancar en QEMU no demuestra compatibilidad con un dispositivo real.

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
