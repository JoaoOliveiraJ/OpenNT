//! PsSetLoadImageNotifyRoutine.
//!
//! 64 slots de rotinas nativas; cada registro ocupa um bloco de pool de 24
//! bytes, liberado quando a remoção encontra o registro sem execuções.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::ntos::ps::process;
use crate::hal::amd64::native_call;
use crate::ntos::ke::{critical_region, dispatcher, irql};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ob::objects::file::{self as file_objects, FileSource};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{ImageInfoEx, UnicodeString};
use super::CallbackBlock;

const SLOTS: usize = 64;

struct Registration {
    pointer: u64,
    callback: u64,
    active: AtomicU32,
    removed: AtomicBool,
    freed: AtomicBool,
}

static REGISTRATIONS: SpinLock<[Option<Arc<Registration>>; SLOTS]> = SpinLock::new([const { None }; SLOTS]);
/// Profundidade de notificações em curso por thread.
static EXECUTING: SpinLock<BTreeMap<u64, u32>> = SpinLock::new(BTreeMap::new());

fn passive() -> Result<(), KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("image notify requires PASSIVE_LEVEL"));
    }
    Ok(())
}

pub fn register(callback: u64) -> Result<u32, KernelError> {
    passive()?;
    let Ok(pointer) = kernel_pool::allocate(CallbackBlock::SIZE, AllocateOptions { tag: 0x6272_6243, zero: true, ..Default::default() }) else {
        return Ok(0xC000_009A);
    };
    let mut slots = REGISTRATIONS.lock();
    let Some(index) = slots.iter().position(Option::is_none) else {
        drop(slots);
        kernel_pool::free(pointer, None)?;
        return Ok(0xC000_009A);
    };
    CallbackBlock::of(pointer).function.set(callback);
    slots[index] = Some(Arc::new(Registration { pointer, callback, active: AtomicU32::new(0), removed: AtomicBool::new(false), freed: AtomicBool::new(false) }));
    Ok(0)
}

fn collect(registration: &Registration) {
    if registration.removed.load(Ordering::Acquire) && registration.active.load(Ordering::Acquire) == 0 && !registration.freed.swap(true, Ordering::AcqRel) {
        let _ = kernel_pool::free(registration.pointer, None);
    }
}

/// Remoção suspensível: conclui quando nenhuma notificação usa o registro.
pub struct RemoveRequest {
    registration: Option<Arc<Registration>>,
}

impl RemoveRequest {
    pub fn poll(&mut self) -> Option<u32> {
        let Some(registration) = &self.registration else { return Some(0xC000_007A) };
        collect(registration);
        registration.freed.load(Ordering::Acquire).then_some(0)
    }

    pub fn cancel(&mut self) {
        if let Some(registration) = &self.registration {
            collect(registration);
        }
    }
}

pub fn begin_remove(callback: u64) -> Result<RemoveRequest, KernelError> {
    if irql::get_irql() > 1 {
        return Err(KernelError::new("image notify removal requires IRQL <= APC_LEVEL"));
    }
    if EXECUTING.lock().get(&process::get_current_thread()).is_some_and(|&depth| depth != 0) {
        return Err(KernelError::new("image notify removal inside a notification"));
    }
    let registration = {
        let mut slots = REGISTRATIONS.lock();
        let index = slots.iter().position(|slot| slot.as_ref().is_some_and(|registration| registration.callback == callback));
        index.and_then(|index| slots[index].take())
    };
    if let Some(registration) = &registration {
        registration.removed.store(true, Ordering::Release);
        collect(registration);
    }
    Ok(RemoveRequest { registration })
}

pub fn remove(callback: u64) -> Result<u32, KernelError> {
    let mut request = begin_remove(callback)?;
    loop {
        if let Some(status) = request.poll() {
            return Ok(status);
        }
        dispatcher::pump_kernel();
    }
}

/// Imagem carregada: base e tamanho.
#[derive(Clone, Copy)]
pub struct Image {
    pub image_base: u64,
    pub size_of_image: u64,
}

#[derive(Clone, Default)]
pub struct NotifyOptions {
    pub no_execute: bool,
    pub name: Option<alloc::string::String>,
    pub file_object: u64,
    pub source: Option<Arc<dyn FileSource>>,
    pub system: bool,
    pub process_id: Option<u64>,
}

/// Monta IMAGE_INFO_EX e chama cada rotina com (FullImageName, ProcessId,
/// ImageInfo) numa região crítica.
pub fn notify(image: Image, options: &NotifyOptions) -> Result<(), KernelError> {
    if options.no_execute || REGISTRATIONS.lock().iter().all(Option::is_none) {
        return Ok(());
    }
    passive()?;
    let thread = process::get_current_thread();
    let mut file = 0u64;
    let mut block = 0u64;
    let mut unicode = 0u64;
    let result = (|| {
        if options.file_object != 0 {
            file = options.file_object;
            file_objects::reference(file)?;
        } else if let Some(source) = &options.source {
            file = file_objects::create_source(source.clone())?;
        }
        block = guest::alloc_bytes(ImageInfoEx::SIZE);
        if block == 0 {
            return Err(KernelError::new("image notification allocation failed"));
        }
        // SAFETY: IMAGE_INFO_EX recém-alocado.
        let extended = unsafe { ImageInfoEx::at(block) };
        let info = extended.image_info.address();
        extended.size.set(ImageInfoEx::SIZE);
        // IMAGE_ADDRESSING_MODE_32BIT vale 3 mesmo em x64; nenhuma decisão de
        // assinatura da CI ocorreu, então nível e tipo ficam zero.
        extended.image_info.properties.set(3 | if options.system { 0x100 } else { 0 } | if file != 0 { 0x400 } else { 0 });
        extended.image_info.image_base.set(image.image_base);
        extended.image_info.image_size.set(image.size_of_image);
        extended.file_object.set(file);
        if let Some(name) = &options.name {
            let units: alloc::vec::Vec<u16> = name.encode_utf16().collect();
            if units.len() > 32766 {
                return Err(KernelError::new("invalid load-image name"));
            }
            unicode = guest::alloc_bytes(UnicodeString::SIZE + units.len() as u64 * 2 + 2);
            if unicode == 0 {
                return Err(KernelError::new("image notification name allocation failed"));
            }
            // SAFETY: UNICODE_STRING recém-alocado, com o buffer logo depois.
            let string = unsafe { UnicodeString::at(unicode) };
            string.length.set(units.len() as u16 * 2);
            string.maximum_length.set(units.len() as u16 * 2 + 2);
            string.buffer.set(unicode + UnicodeString::SIZE);
            let characters: alloc::vec::Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
            guest::write_bytes(unicode + UnicodeString::SIZE, &characters);
        }
        let process_id = if options.system { 0 } else { options.process_id.unwrap_or_else(process::get_current_process_id) };
        critical_region::enter_critical()?;
        *EXECUTING.lock().entry(thread).or_insert(0) += 1;
        for index in 0..SLOTS {
            let Some(registration) = REGISTRATIONS.lock()[index].clone() else { continue };
            registration.active.fetch_add(1, Ordering::AcqRel);
            native_call::call(registration.callback, &[unicode, process_id, info]);
            registration.active.fetch_sub(1, Ordering::AcqRel);
            collect(&registration);
        }
        {
            let mut executing = EXECUTING.lock();
            if let Some(depth) = executing.get_mut(&thread) {
                *depth -= 1;
                if *depth == 0 {
                    executing.remove(&thread);
                }
            }
        }
        critical_region::leave_critical()
    })();
    if file != 0 {
        let _ = file_objects::dereference(file);
    }
    if unicode != 0 {
        guest::free_bytes(unicode);
    }
    if block != 0 {
        guest::free_bytes(block);
    }
    result
}
