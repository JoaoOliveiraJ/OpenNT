# Installer OpenNT

> [English](../../INSTALL.md) | [中文](../zh-CN/INSTALL.md) | **Français** | [Español](../es-ES/INSTALL.md) | [日本語](../ja-JP/INSTALL.md) | [العربية](../ar-MA/INSTALL.md)

## Compiler les images

Préparez l'environnement de compilation et configurez une compilation comme décrit dans [Compiler OpenNT vous-même](README.md#compiler-opennt-vous-même). Compilez ensuite l'image dont vous avez besoin depuis le dossier de sortie, par exemple `output-Clang-amd64-debug` :

| Commande | Crée | Pour |
|---|---|---|
| `ninja bootcd` | `bootcd.iso` | Lancer OpenNT depuis une image de CD, ou y démarrer l'installation de OpenNT et installer OpenNT sur un disque. |
| `ninja openntimg` | `OpenNT.img` | Démarrer un disque où OpenNT est déjà installé. Il démarre en UEFI ou en BIOS. |
| `ninja openntvhd` | `OpenNT.vhd`, `OpenNT.vhdx` | Utiliser le même disque préinstallé dans des machines virtuelles : le VHD dans VirtualBox et Hyper-V génération 1, le VHDX dans Hyper-V génération 2, qui n'accepte pas les disques VHD. |

Chaque cible compile d'abord tout ce dont elle a besoin, et les fichiers sont écrits dans le dossier de sortie.

## Installer depuis le CD d'installation

Démarrez `bootcd.iso` dans une machine virtuelle ou sur un PC, et suivez les instructions de l'installation de OpenNT. L'installation affiche les disques comme le programme d'installation de Windows, et peut créer, supprimer, formater, réduire et étendre des partitions. Elle installe OpenNT sur NTFS et crée la partition système EFI dont il a besoin.

## Utiliser le disque préinstallé

`OpenNT.img` ne nécessite aucune installation. Lancez-le dans une machine virtuelle comme QEMU, ou écrivez-le sur une clé USB ou une carte SD et démarrez la machine dessus. Utilisez `OpenNT.vhd` pour les machines virtuelles qui acceptent les disques VHD, et `OpenNT.vhdx` pour les machines virtuelles Hyper-V génération 2, avec le démarrage sécurisé désactivé.

Le disque préinstallé contient aussi l'installation de OpenNT. Lancez `C:\<architecture>\opennt.exe`, par exemple `C:\arm64\opennt.exe`, pour installer OpenNT sur un autre disque depuis le système en cours d'exécution.

## Aide

En cas de problème, signalez-le dans les [GitHub Issues](https://github.com/JoaoOliveiraJ/OpenNT/issues) en précisant l'architecture, le type de compilation, le commit que vous avez compilé et les étapes qui mènent au problème. Les guides et les notes se trouvent dans le [dossier de documentation](https://github.com/JoaoOliveiraJ/OpenNT/tree/main/doc), et vous pouvez interroger l'équipe sur [GitHub Issues](https://github.com/JoaoOliveiraJ/OpenNT/issues).
