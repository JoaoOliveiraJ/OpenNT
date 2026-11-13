//! Drivers internos: vídeo VGA em modo texto, console, teclado PS/2,
//! barramentos (PCI, placa-mãe), disco ATA e os sistemas de arquivos
//! (`fs`). Os drivers reais do Windows (i8042prt, kbdclass, atapi, disk...)
//! sobem do volume NTFS pelo I/O Manager.

pub mod bus;
pub mod console;
pub mod input;
pub mod video;
pub mod storage;
pub mod fs;
