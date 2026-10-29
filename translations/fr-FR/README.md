# OpenNT

**Un système d'exploitation NT libre, axé sur la compatibilité avec Windows 10 et les versions ultérieures, y compris leurs pilotes.**

OpenNT développe le noyau, les services système, l'environnement Win32 et les interfaces nécessaires aux applications et aux pilotes modernes. AMD64 (x86-64) est la plateforme principale de développement. Les ports ARM64, RISC-V64 et les autres architectures héritées restent dans le projet.

La prise en charge des pilotes Windows 10+ est un objectif de développement : tous les pilotes ne fonctionnent pas encore. Chaque pilote doit être testé avec son matériel et la version de Windows ciblée. Un démarrage réussi dans QEMU ne prouve pas la compatibilité avec un périphérique réel.

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
