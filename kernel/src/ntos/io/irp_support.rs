//! Suporte a IRPs do I/O Manager.
//!
//! IRPs associados (IoMakeAssociatedIrp e a conclusão que devolve a contagem
//! ao mestre), a dica de prioridade de I/O guardada em Irp->Flags, a extensão
//! de crypto engine do adaptador e o ajuste de StackSize de uma pilha que
//! redireciona IRPs para outra (IoAdjustStackSizeForRedirection).
//!
//! Comportamento conferido contra o ntoskrnl 19041:
//!   IoMakeAssociatedIrp            rva 0x5058d0 -> IoMakeAssociatedIrpPriv 0x2e6098
//!   IopfCompleteRequest (ramo IRP_ASSOCIATED_IRP)   rva 0x243016..0x243069
//!   IoSetIoPriorityHint            rva 0x2faba0
//!   IoGetIoPriorityHint            rva 0x2547c0
//!   IoGetAdapterCryptoEngineExtension rva 0x5077f0
//!   IoAdjustStackSizeForRedirection   rva 0x505390
//!
//! Os IRPs do OpenNT vêm da arena (`guest::alloc_bytes`, zerada) como no
//! IoAllocateIrp do OpenNT. As extensões embutidas no IRP
//! (`Irp->Tail.Overlay.IrpExtension`) são as do `io::extensions`; o caminho do
//! NT que reserva duas posições de pilha extras para as extensões de
//! atribuição de disco e de flags de driver (tipos 6/8 no mestre) não se
//! aplica porque nenhum componente do OpenNT anexa esses dois tipos.

use core::sync::atomic::Ordering;

use crate::ntos::inc::types::extra_io::IrpExtensionField;
use crate::ntos::inc::types::extra_fs_ntfs::IopIrpExtension;
use crate::ntos::inc::types::{DeviceObject, Irp, IoStackLocation, Mdl, NtStruct};
use crate::ntos::init::exports::invoke_handler;
use crate::ntos::io::io_manager;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::device as device_objects;
use crate::rtl::KernelError;

/// IO_TYPE_IRP.
const IO_TYPE_IRP: i16 = 6;
/// Irp->Flags.
const IRP_ASSOCIATED_IRP: u32 = 0x0000_0008;
/// Bits herdados do mestre: IRP_NOCACHE | IRP_HOLD_DEVICE_QUEUE |
/// IRP_UM_DRIVER_INITIATED_IO | IRP_CLASS_CACHE_OPERATION (and 0xE0002).
const IRP_INHERITED_FLAGS: u32 = 0x000E_0002;
/// Campo de prioridade em Flags: (hint + 1) << 17, três bits.
const IRP_PRIORITY_SHIFT: u32 = 17;
const IRP_PRIORITY_MASK: u32 = 0x000E_0000;
/// IO_PRIORITY_HINT: IoPriorityVeryLow..IoPriorityCritical; MaxIoPriorityTypes = 5.
const MAX_IO_PRIORITY_TYPES: u32 = 5;
const IO_PRIORITY_NORMAL: u32 = 2;
/// Tipo de extensão AdapterCryptoParameters.
const IRP_EXTENSION_ADAPTER_CRYPTO: u32 = 7;
/// Limite de StackSize do NT (o mesmo do IoAttachDeviceToDeviceStack).
const MAXIMUM_STACK_SIZE: u32 = 0x7D;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;

/// DEVICE_OBJECT vivo da pilha (dispositivos registrados no Ob).
fn device_at(device: u64) -> &'static DeviceObject {
    // SAFETY: os chamadores passam DEVICE_OBJECTs vivos.
    unsafe { DeviceObject::at(device) }
}

/// IoMakeAssociatedIrp(MasterIrp, StackSize): IRP novo com StackSize
/// posições, marcado IRP_ASSOCIATED_IRP, herdando a thread e os bits de
/// cache do mestre e apontando para ele em AssociatedIrp.MasterIrp. Quem
/// chama ajusta MasterIrp->AssociatedIrp.IrpCount. NULL sem memória.
pub fn make_associated_irp(master_address: u64, stack_size: u8) -> u64 {
    // SAFETY: o mestre é um IRP vivo do chamador.
    let master = unsafe { Irp::at(master_address) };
    let count = (stack_size as i8).max(1) as u64;
    let size = Irp::SIZE + count * IoStackLocation::SIZE;
    let packet = guest::alloc_bytes(size);
    if packet == 0 {
        return 0;
    }
    // SAFETY: bloco recém-alocado e zerado do tamanho do IRP com as posições.
    let irp = unsafe { Irp::at(packet) };
    irp.type_.set(IO_TYPE_IRP);
    irp.size.set(size as u16);
    // AllocationProcessorNumber (o _pad_4 do Size): o código de driver do
    // OpenNT roda no BSP, o mesmo que KeGetCurrentProcessorNumber devolve; o
    // bloco já vem zerado.
    irp.stack_count.set(count as i8);
    irp.current_location.set(count as i8 + 1);
    // OriginalApcEnvironment: o OpenNT não anexa threads de sistema a outros
    // processos durante o I/O de drivers.
    irp.apc_environment.set(0);
    let list_head = irp.thread_list_entry.flink.address();
    irp.thread_list_entry.flink.set(list_head);
    irp.thread_list_entry.blink.set(list_head);
    irp.tail.overlay.current_stack_location.set(packet + size);
    irp.flags.set(IRP_ASSOCIATED_IRP | (master.flags.get() & IRP_INHERITED_FLAGS));
    irp.tail.overlay.thread.set(master.tail.overlay.thread.get());
    irp.associated_irp.master_irp.set(master_address);
    packet
}

/// Ramo IRP_ASSOCIATED_IRP do IopfCompleteRequest, depois das rotinas de
/// conclusão do associado: libera a cadeia de MDLs e o IRP, decrementa
/// MasterIrp->AssociatedIrp.IrpCount (lock xadd) e completa o mestre quando a
/// contagem chega a zero. `false` = não é associado (segue a conclusão normal).
pub fn complete_associated_irp(packet: u64) -> Result<bool, KernelError> {
    // SAFETY: IRP em conclusão (vivo até o IoFreeIrp abaixo).
    let irp = unsafe { Irp::at(packet) };
    if irp.flags.get() & IRP_ASSOCIATED_IRP == 0 {
        return Ok(false);
    }
    let master_address = irp.associated_irp.master_irp.get();
    // MDLs do OpenNT vêm da arena: IoFreeMdl é a liberação do bloco.
    let mut mdl = irp.mdl_address.get();
    while mdl != 0 {
        // SAFETY: MDL da cadeia do IRP, viva até ser liberada aqui.
        let next = unsafe { Mdl::at(mdl) }.next.get();
        guest::free_bytes(mdl);
        mdl = next;
    }
    irp.mdl_address.set(0);
    invoke_handler("IoFreeIrp", &[packet])?;
    // SAFETY: o mestre continua vivo enquanto tiver associados pendentes.
    let master = unsafe { Irp::at(master_address) };
    let previous = master.associated_irp.irp_count.atomic().fetch_sub(1, Ordering::SeqCst);
    if previous == 1 {
        io_manager::iof_complete_request(master_address);
    }
    Ok(true)
}

/// IoSetIoPriorityHint(Irp, PriorityHint).
pub fn set_io_priority_hint(irp: &Irp, hint: u32) -> u32 {
    if hint >= MAX_IO_PRIORITY_TYPES {
        return STATUS_INVALID_PARAMETER;
    }
    let flags = irp.flags.get() & !IRP_PRIORITY_MASK;
    irp.flags.set(flags | ((hint << IRP_PRIORITY_SHIFT) + (1 << IRP_PRIORITY_SHIFT)));
    STATUS_SUCCESS
}

/// IoGetIoPriorityHint(Irp): campo de Flags menos um; sem dica gravada,
/// IoPriorityNormal. O NT ainda promove VeryLow/Low a Normal quando a thread
/// do IRP tem ETHREAD.IoBoostCount != 0; o OpenNT nunca aplica boost de I/O
/// por inversão de prioridade (contagem sempre zero).
pub fn get_io_priority_hint(irp: &Irp) -> u32 {
    let field = (irp.flags.get() & IRP_PRIORITY_MASK) >> IRP_PRIORITY_SHIFT;
    if field == 0 { IO_PRIORITY_NORMAL } else { field - 1 }
}

/// IoGetAdapterCryptoEngineExtension(Irp, Extension*): com a extensão tipo 7
/// (AdapterCryptoParameters) presente, devolve o endereço da união em
/// IrpExtension+0x28 (AdapterCryptoParameters, a mesma célula que o
/// FsTrackOffsetBlob abre); senão STATUS_NOT_FOUND.
pub fn get_adapter_crypto_engine_extension(irp: &Irp, output: u64) -> u32 {
    if !crate::ntos::io::extensions::irp_has_extension_type(irp.address(), IRP_EXTENSION_ADAPTER_CRYPTO) {
        return STATUS_NOT_FOUND;
    }
    // SAFETY: com o tipo 7 alocado, IrpExtension aponta para a extensão viva.
    let extension = unsafe { IopIrpExtension::at(irp.irp_extension().get()) };
    // SAFETY: PVOID* de saída de um chamador de modo kernel.
    let output = unsafe { crate::ntos::inc::types::Field::<u64>::at(output) };
    output.set(extension.fs_track_offset_blob.address());
    STATUS_SUCCESS
}

/// IoAdjustStackSizeForRedirection(SourceDevice, TargetDevice, Delta*): sob
/// o lock da base de dispositivos, soma a diferença de StackSize a cada
/// dispositivo da pilha da origem (do topo até a origem), recusando com
/// STATUS_INVALID_PARAMETER se o topo passaria do limite.
pub fn adjust_stack_size_for_redirection(source_address: u64, target_address: u64, delta_output: u64) -> Result<u32, KernelError> {
    let source = device_at(source_address);
    let target = device_at(target_address);
    let (status, delta) = device_objects::with_lock(|| {
        let source_size = source.stack_size.get();
        let target_size = target.stack_size.get();
        if source_size >= target_size {
            return Ok((STATUS_SUCCESS, 0i8));
        }
        let delta = target_size.wrapping_sub(source_size);
        let top = device_at(device_objects::top(source_address));
        // movsx + movzx de 16 bits, como o original.
        if top.stack_size.get() as i16 as u16 as u32 + delta as i16 as u16 as u32 >= MAXIMUM_STACK_SIZE {
            return Ok((STATUS_INVALID_PARAMETER, delta));
        }
        // Do topo até a origem por DeviceObjectExtension->AttachedTo.
        let mut device = top.address();
        while device != source_address && device != 0 {
            let current = device_at(device);
            current.stack_size.set(current.stack_size.get().wrapping_add(delta));
            // SAFETY: DEVOBJ_EXTENSION do dispositivo registrado.
            device = unsafe { crate::ntos::inc::types::DevobjExtension::at(current.device_object_extension.get()) }.attached_to.get();
        }
        source.stack_size.set(source.stack_size.get().wrapping_add(delta));
        Ok((STATUS_SUCCESS, delta))
    })?;
    if status == STATUS_SUCCESS && delta_output != 0 {
        // SAFETY: PCHAR de saída de um chamador de modo kernel.
        unsafe { crate::ntos::inc::types::Field::<i8>::at(delta_output) }.set(delta);
    }
    Ok(status)
}

// ---- IoMakeAssociatedIrpEx (io-paging) ---------------------------------------
//
// Autocontido (tipos por caminho qualificado, nomes com prefixo
// `associated_`/`ASSOCIATED_`); usa o `make_associated_irp` deste módulo.

/// DEVICE_OBJECT.Flags: DO_DEVICE_IRP_REQUIRES_EXTENSION.
const ASSOCIATED_REQUIRES_EXTENSION: u32 = 0x0800_0000;
/// Tipos de extensão que o NT copia do mestre para a extensão embutida.
const ASSOCIATED_DISK_IO_ATTRIBUTION: u32 = 6;
const ASSOCIATED_DRIVER_FLAGS: u32 = 8;
/// Duas stack locations no topo guardam a _IOP_IRP_EXTENSION embutida.
const ASSOCIATED_EMBEDDED_LOCATIONS: i8 = 2;

/// IoMakeAssociatedIrpEx(MasterIrp, DeviceObject, StackSize) -> o mesmo
/// IoMakeAssociatedIrpPriv (RVA 0x2e6098): quando o mestre tem atribuição de
/// disco/flags de driver ou o dispositivo exige extensão, o associado nasce
/// com StackSize + 2 posições e as duas do topo viram a extensão embutida
/// (StackCount/CurrentLocation -2, CurrentStackLocation e IrpExtension
/// apontando para elas). As cópias dos tipos 6/8 do mestre não se aplicam:
/// nenhum componente do OpenNT anexa esses tipos.
pub fn make_associated_irp_ex(master: &crate::ntos::inc::types::Irp, device: Option<&crate::ntos::inc::types::DeviceObject>, stack_size: u8) -> u64 {
    use crate::ntos::inc::field::NtStruct;
    use crate::ntos::inc::types::extra_io::IrpExtensionField;
    let embedded = crate::ntos::io::extensions::irp_extension_of_type(master, ASSOCIATED_DISK_IO_ATTRIBUTION).is_some()
        || crate::ntos::io::extensions::irp_extension_of_type(master, ASSOCIATED_DRIVER_FLAGS).is_some()
        || device.is_some_and(|device| device.flags.get() & ASSOCIATED_REQUIRES_EXTENSION != 0);
    if !embedded {
        return make_associated_irp(master.address(), stack_size);
    }
    let packet = make_associated_irp(master.address(), stack_size.wrapping_add(ASSOCIATED_EMBEDDED_LOCATIONS as u8));
    if packet == 0 {
        return 0;
    }
    // SAFETY: IRP associado recém-criado.
    let associated = unsafe { crate::ntos::inc::types::Irp::at(packet) };
    associated.stack_count.set(associated.stack_count.get().wrapping_sub(ASSOCIATED_EMBEDDED_LOCATIONS));
    associated.current_location.set(associated.current_location.get().wrapping_sub(ASSOCIATED_EMBEDDED_LOCATIONS));
    let current = associated.tail.overlay.current_stack_location.get() - ASSOCIATED_EMBEDDED_LOCATIONS as u64 * crate::ntos::inc::types::IoStackLocation::SIZE;
    associated.tail.overlay.current_stack_location.set(current);
    associated.irp_extension().set(current);
    packet
}
