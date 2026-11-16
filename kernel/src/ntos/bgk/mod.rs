//! Boot Graphics Kernel (Bgk): o lado do kernel da biblioteca gráfica de
//! boot — o console de texto sobre o vídeo de boot que o condrv.sys usa
//! quando o console vai para a tela de boot (`console`), a informação do
//! vídeo de boot da classe SystemBootGraphicsInformation
//! (`graphics_information`), a fonte do vídeo de boot (`boot_font`) e a
//! tela de bugcheck (`bugcheck_screen`).

pub mod boot_font;
pub mod bugcheck_screen;
pub mod console;
pub mod exports;
pub mod graphics_information;
