//! Sistemas de arquivos — como no NT, drivers fora do núcleo do kernel.
//!
//! O MemoryFileSystem (RAMFS) do boot, a interface de volume montável, os
//! nomes nativos de arquivo e o NTFS de leitura e escrita sobre o driver ATA.

pub mod memory_file_system;
pub mod native_file_name;
pub mod volume;
pub mod ntfs;
pub mod extended_attributes;
pub mod ntfs_write;
pub mod ntfs_control;
pub mod volume_information;
pub mod filter_callbacks;
pub mod volume_files;
