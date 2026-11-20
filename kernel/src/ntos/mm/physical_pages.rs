//! As páginas físicas de usuário (AWE, Address Windowing Extensions) do
//! ntoskrnl 19041.
//!
//! Uma seção de páginas físicas de usuário (o UserPhysicalFlags do
//! NtCreateSectionEx, `mm/section/create`) chega aqui depois das checagens
//! de atributos, proteção e do SeLockMemoryPrivilege: sem o privilégio,
//! STATUS_PRIVILEGE_NOT_HELD, como no MiCreatePagingFileMap (0x61ca30). O
//! OpenNT ainda não tem a AweInfo de seção (o MiAllocateAweInfo da seção e
//! as vistas AWE): com o privilégio, a criação para na fronteira
//! (`[awe-boundary]`, STATUS_NOT_SUPPORTED).

const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

/// O fim do MiCreatePagingFileMap de uma seção com UserPhysicalFlags:
/// `privileged` é o SeSinglePrivilegeCheck(SeLockMemoryPrivilege).
pub fn user_physical_section(privileged: bool) -> u32 {
    if !privileged {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    debug_print!("[awe-boundary] secao de paginas fisicas de usuario (MiAllocateAweInfo da secao) ainda sem suporte");
    STATUS_NOT_SUPPORTED
}
