# Installing OpenNT

> **English** | [中文](translations/zh-CN/INSTALL.md) | [Français](translations/fr-FR/INSTALL.md) | [Español](translations/es-ES/INSTALL.md) | [日本語](translations/ja-JP/INSTALL.md) | [العربية](translations/ar-MA/INSTALL.md)

## Building the images

Set up the build environment and configure a build as described in [Building](README.md#building). Then build the image you need from the output folder, for example `output-Clang-amd64-debug`:

| Command | Creates | Use it to |
|---|---|---|
| `ninja bootcd` | `bootcd.iso` | Run OpenNT from a CD image, or start OpenNT Setup from it and install OpenNT on a disk. |
| `ninja openntimg` | `OpenNT.img` | Boot a disk with OpenNT already installed. It boots with UEFI or BIOS. |
| `ninja openntvhd` | `OpenNT.vhd`, `OpenNT.vhdx` | Use the same preinstalled disk in virtual machines: the VHD in VirtualBox and Hyper-V Generation 1, the VHDX in Hyper-V Generation 2, which does not take VHD disks. |

Each target builds everything it needs first, and the files are written to the output folder.

## Installing from the setup CD

Boot `bootcd.iso` in a virtual machine or on a PC, and follow the instructions of OpenNT Setup. Setup lists the drives the way Windows Setup does, and can create, delete, format, shrink and extend partitions. It installs OpenNT on NTFS and creates the EFI system partition it needs.

## Using the preinstalled disk

`OpenNT.img` needs no setup. Start it in a virtual machine such as QEMU, or write it to a USB drive or an SD card and boot the machine from it. Use `OpenNT.vhd` for virtual machines that take VHD disks, and `OpenNT.vhdx` for Hyper-V Generation 2 virtual machines, with Secure Boot turned off.

The preinstalled disk also carries OpenNT Setup. Run `C:\<architecture>\opennt.exe`, for example `C:\arm64\opennt.exe`, to install OpenNT on another disk from the running system.

## Help

If something goes wrong, report it in [GitHub Issues](https://github.com/JoaoOliveiraJ/OpenNT/issues) with the architecture, the build type, the commit you built and the steps that lead to the problem. Guides and notes are in the [Documentation](https://github.com/JoaoOliveiraJ/OpenNT/tree/main/doc), and you can ask the team on [GitHub Issues](https://github.com/JoaoOliveiraJ/OpenNT/issues).
