//! Os árbitros e tradutores de recursos dos drivers de barramento.
//!
//! Como o IopSetupArbiterAndTranslators do ntoskrnl 19041 (rva 0x75152c),
//! cada requisito de um nó acha quem o arbitra e quem o traduz subindo a
//! árvore a partir do próprio nó:
//! - em cada ancestral (o próprio nó não arbitra os próprios recursos) o
//!   PnP pergunta à pilha pelo árbitro do tipo (IRP_MN_QUERY_INTERFACE com
//!   GUID_ARBITER_INTERFACE_STANDARD, Size 0x30, Version 0 e o tipo do
//!   recurso em InterfaceSpecificData, o IopQueryResourceHandlerInterface);
//!   o primeiro que responde arbitra. Um árbitro parcial (ARBITER_PARTIAL,
//!   como os do pci.sys) responde ao ArbiterActionQueryArbitrate se o
//!   pedido é dele (o do pci.sys, se cabe nas janelas da ponte); se não, a
//!   busca continua acima;
//! - em cada nó, a partir do próprio, o PnP pergunta pelo tradutor do tipo
//!   (GUID_TRANSLATOR_INTERFACE_STANDARD, Size 0x34). Abaixo do árbitro, o
//!   tradutor converte o requisito para o espaço do pai
//!   (TranslateResourceRequirements, o IopTranslateAndAdjustReqDesc);
//!   STATUS_TRANSLATION_COMPLETE encerra a busca de tradutores;
//! - na raiz, sem árbitro de driver, arbitram os árbitros da raiz
//!   (`resources::place_at_root`, os IopRoot*Arbiter); o tradutor da raiz é
//!   a identidade, com a tradução de linhas da HAL sem ACPI.
//! As respostas ficam por nó e tipo (DeviceArbiterList/DeviceTranslatorList
//! e as máscaras Query/No do DEVICE_NODE); só um PDO com
//! DO_BUS_ENUMERATED_DEVICE é perguntado.
//!
//! A atribuição de uma lista alternativa é a do IopTestConfiguration e do
//! IopCommitConfiguration: os requisitos de cada árbitro de driver vão numa
//! lista de ARBITER_LIST_ENTRY (as alternativas, o PDO, a origem
//! ArbiterRequestPnpEnumerated, o barramento e o CM_PARTIAL_RESOURCE_
//! DESCRIPTOR de saída em Assignment) ao ArbiterHandler com
//! ArbiterActionTestAllocation; se todos os árbitros aceitam, cada um
//! recebe ArbiterActionCommitAllocation; se um recusa, os que aceitaram
//! recebem ArbiterActionRollbackAllocation e a próxima lista alternativa é
//! tentada. O recurso atribuído no espaço do árbitro volta ao espaço do
//! dispositivo pelos tradutores abaixo dele (ParentToChild, o
//! IopParentToRawTranslation): a lista bruta. A traduzida passa cada recurso
//! bruto pelos tradutores do nó até a raiz (ChildToParent, o
//! IopChildToRootTranslation) até um STATUS_TRANSLATION_COMPLETE.
//!
//! Uma interrupção de linha traduzida por um driver (o tradutor do acpi.sys
//! dá o vetor do IDT que o árbitro de IRQ dele escolheu) fica registrada na
//! HAL com a linha bruta (`hal::interrupt_lines::route_vector`): a conexão
//! nesse vetor recebe a linha do controlador.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::devnode;
use super::irp;
use super::resources::{self, resource_type, Choice, CmList, Requirements, Resource};
use crate::hal::amd64::native_call;
use crate::ntos::inc::types::extra_storage::TranslatorInterface;
use crate::ntos::inc::types::{ArbiterInterface, ArbiterListEntry, ArbiterParameters, ArbiterRequestSource, ArbiterResult, CmPartialResourceDescriptor, DeviceObject, InterfaceType, IoResourceDescriptor, ListEntry, NtStruct};
use crate::ntos::io::io_manager::irp_mn;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::{KernelError, SpinLock};

/// GUID_ARBITER_INTERFACE_STANDARD {e644f185-8c0e-11d0-becf-08002be2092f}.
const GUID_ARBITER_INTERFACE_STANDARD: [u8; 16] = [0x85, 0xF1, 0x44, 0xE6, 0x0E, 0x8C, 0xD0, 0x11, 0xBE, 0xCF, 0x08, 0x00, 0x2B, 0xE2, 0x09, 0x2F];
/// GUID_TRANSLATOR_INTERFACE_STANDARD {6c154a92-aacf-11d0-8d2a-00a0c906b244}.
const GUID_TRANSLATOR_INTERFACE_STANDARD: [u8; 16] = [0x92, 0x4A, 0x15, 0x6C, 0xCF, 0xAA, 0xD0, 0x11, 0x8D, 0x2A, 0x00, 0xA0, 0xC9, 0x06, 0xB2, 0x44];

/// Tamanhos pedidos pelo IopQueryResourceHandlerInterface.
const ARBITER_INTERFACE_SIZE: u16 = 0x30;
const TRANSLATOR_INTERFACE_SIZE: u16 = 0x34;
const DO_BUS_ENUMERATED_DEVICE: u32 = 0x1000;
/// ARBITER_INTERFACE.Flags: o árbitro só aceita parte dos pedidos do tipo.
const ARBITER_PARTIAL: u32 = 1;
const STATUS_TRANSLATION_COMPLETE: i32 = 0x120;
/// CM_RESOURCE_INTERRUPT_MESSAGE: interrupção por mensagem (MSI), sem linha.
const CM_RESOURCE_INTERRUPT_MESSAGE: u16 = 2;

/// ARBITER_ACTION.
pub mod action {
    pub const TEST_ALLOCATION: u64 = 0;
    pub const COMMIT_ALLOCATION: u64 = 2;
    pub const ROLLBACK_ALLOCATION: u64 = 3;
    pub const QUERY_ARBITRATE: u64 = 7;
}

/// RESOURCE_TRANSLATION_DIRECTION.
const TRANSLATE_CHILD_TO_PARENT: u64 = 0;
const TRANSLATE_PARENT_TO_CHILD: u64 = 1;

/// O tipo de tratador (o RESOURCE_HANDLER_TYPE do NT).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Kind {
    Translator = 1,
    Arbiter = 2,
}

/// Respostas por (PDO do nó, tratador, tipo de recurso): a interface
/// entregue pela pilha, ou 0 quando ela não tem tratador do tipo.
static HANDLERS: SpinLock<BTreeMap<(u64, Kind, u8), u64>> = SpinLock::new(BTreeMap::new());
/// Árbitros de driver que guardam recursos de cada PDO.
static HELD: SpinLock<BTreeMap<u64, Vec<u64>>> = SpinLock::new(BTreeMap::new());
static ARBITER_GUID: AtomicU64 = AtomicU64::new(0);
static TRANSLATOR_GUID: AtomicU64 = AtomicU64::new(0);

/// O GUID numa cópia do kernel (o InterfaceType do pedido é um ponteiro).
fn guid_address(kind: Kind) -> u64 {
    let (cell, bytes) = match kind {
        Kind::Arbiter => (&ARBITER_GUID, &GUID_ARBITER_INTERFACE_STANDARD),
        Kind::Translator => (&TRANSLATOR_GUID, &GUID_TRANSLATOR_INTERFACE_STANDARD),
    };
    let current = cell.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    let block = guest::alloc_bytes(16);
    guest::write_bytes(block, bytes);
    match cell.compare_exchange(0, block, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => block,
        Err(winner) => {
            guest::free_bytes(block);
            winner
        }
    }
}

/// IopQueryResourceHandlerInterface: o tratador do tipo que a pilha do nó
/// entrega (0 = nenhum), com a resposta guardada por nó.
fn query_handler(kind: Kind, pdo: u64, resource: u8) -> Result<u64, KernelError> {
    if let Some(&interface) = HANDLERS.lock().get(&(pdo, kind, resource)) {
        return Ok(interface);
    }
    // SAFETY: PDO de um nó da árvore.
    let enumerated = unsafe { DeviceObject::at(pdo) }.flags.get() & DO_BUS_ENUMERATED_DEVICE != 0;
    let mut interface = 0;
    if enumerated {
        let size = match kind {
            Kind::Arbiter => ARBITER_INTERFACE_SIZE,
            Kind::Translator => TRANSLATOR_INTERFACE_SIZE,
        };
        let buffer = guest::alloc_bytes(size as u64);
        guest::write16(buffer, size);
        let guid = guid_address(kind);
        let outcome = irp::synchronous_call(pdo, irp_mn::QUERY_INTERFACE, 0, |location| {
            let parameters = &location.parameters.query_interface;
            parameters.interface_type.set(guid);
            parameters.size.set(size);
            parameters.version.set(0);
            parameters.interface.set(buffer);
            parameters.interface_specific_data.set(resource as u64);
        })?;
        let complete = match kind {
            // SAFETY: interface preenchida pela pilha no buffer acima.
            Kind::Arbiter => unsafe { ArbiterInterface::at(buffer) }.arbiter_handler.get() != 0,
            Kind::Translator => {
                // SAFETY: idem.
                let translator = unsafe { TranslatorInterface::at(buffer) };
                translator.translate_resources.get() != 0 && translator.translate_resource_requirements.get() != 0
            }
        };
        if outcome.succeeded() && complete {
            interface = buffer;
            debug_print!("[pnp] {:?} do tipo {} na pilha de {}: {:#x}", kind, resource, devnode::get(pdo).map(|node| node.instance_path).unwrap_or_default(), interface);
        } else {
            guest::free_bytes(buffer);
        }
    }
    HANDLERS.lock().insert((pdo, kind, resource), interface);
    Ok(interface)
}

/// Uma lista de IO_RESOURCE_DESCRIPTOR contígua em pool.
#[derive(Clone, Copy)]
struct Descriptors {
    address: u64,
    count: u32,
}

impl Descriptors {
    /// Cópia das opções de um requisito (as montadas à mão são escritas).
    fn copy_of(need: &[Choice]) -> Descriptors {
        let address = guest::alloc_bytes(need.len().max(1) as u64 * IoResourceDescriptor::SIZE);
        for (index, choice) in need.iter().enumerate() {
            let target = address + index as u64 * IoResourceDescriptor::SIZE;
            if choice.address != 0 {
                guest::write_bytes(target, &guest::read_bytes(choice.address, IoResourceDescriptor::SIZE as usize));
            } else {
                write_choice(target, choice);
            }
            // As alternativas seguem a primeira opção (IO_RESOURCE_ALTERNATIVE).
            // SAFETY: descritor recém-copiado.
            let descriptor = unsafe { IoResourceDescriptor::at(target) };
            descriptor.option.set(if index == 0 { descriptor.option.get() & !IO_RESOURCE_ALTERNATIVE } else { descriptor.option.get() | IO_RESOURCE_ALTERNATIVE });
        }
        Descriptors { address, count: need.len() as u32 }
    }

    fn at(&self, index: u32) -> u64 {
        self.address + index as u64 * IoResourceDescriptor::SIZE
    }

    fn free(self) {
        guest::free_bytes(self.address);
    }
}

/// IO_RESOURCE_DESCRIPTOR.Option: alternativa do descritor anterior.
const IO_RESOURCE_ALTERNATIVE: u8 = 0x08;

/// Escreve uma opção montada à mão como IO_RESOURCE_DESCRIPTOR.
fn write_choice(address: u64, choice: &Choice) {
    // SAFETY: descritor do chamador.
    let descriptor = unsafe { IoResourceDescriptor::at(address) };
    descriptor.type_.set(choice.resource_type);
    descriptor.share_disposition.set(choice.share);
    descriptor.flags.set(choice.flags);
    match choice.resource_type {
        resource_type::PORT | resource_type::MEMORY => {
            let port = &descriptor.u.port;
            port.length.set(choice.length);
            port.alignment.set(choice.alignment as u32);
            port.minimum_address.quad_part.set(choice.minimum as i64);
            port.maximum_address.quad_part.set(choice.maximum as i64);
        }
        resource_type::INTERRUPT => {
            descriptor.u.interrupt.minimum_vector.set(choice.minimum as u32);
            descriptor.u.interrupt.maximum_vector.set(choice.maximum as u32);
            descriptor.u.interrupt.targeted_processors.set(choice.affinity);
        }
        _ => {}
    }
}

/// As opções de uma lista de descritores.
fn choices_of(descriptors: Descriptors) -> Vec<Choice> {
    (0..descriptors.count).map(|index| resources::choice_at(descriptors.at(index))).collect()
}

/// Um ARBITER_LIST_ENTRY com o CM_PARTIAL_RESOURCE_DESCRIPTOR de saída logo
/// depois dele, na mesma alocação.
fn new_entry(pdo: u64, header: &Requirements, descriptors: Descriptors) -> u64 {
    let entry = guest::alloc_bytes(ArbiterListEntry::SIZE + CmPartialResourceDescriptor::SIZE);
    // SAFETY: bloco recém-alocado e zerado.
    let fields = unsafe { ArbiterListEntry::at(entry) };
    fields.list_entry.flink.set(entry);
    fields.list_entry.blink.set(entry);
    fields.alternative_count.set(descriptors.count);
    fields.alternatives.set(if descriptors.count == 0 { 0 } else { descriptors.address });
    fields.physical_device_object.set(pdo);
    fields.request_source.set(ArbiterRequestSource::ARBITER_REQUEST_PNP_ENUMERATED);
    fields.interface_type.set(InterfaceType(header.interface_type));
    fields.slot_number.set(header.slot_number);
    fields.bus_number.set(header.bus_number);
    fields.assignment.set(entry + ArbiterListEntry::SIZE);
    fields.result.set(ArbiterResult::ARBITER_RESULT_UNDEFINED);
    entry
}

/// O ArbiterHandler de um árbitro com uma lista de entradas (ou nenhuma).
fn call_arbiter(interface: u64, action: u64, entries: &[u64]) -> i32 {
    // SAFETY: ARBITER_INTERFACE entregue pela pilha.
    let arbiter = unsafe { ArbiterInterface::at(interface) };
    let parameters = guest::alloc_bytes(ArbiterParameters::SIZE);
    let head = guest::alloc_bytes(ListEntry::SIZE);
    let list = (!entries.is_empty() || action == action::TEST_ALLOCATION || action == action::QUERY_ARBITRATE).then_some(head);
    if let Some(head) = list {
        // A cabeça e as entradas formam a lista circular.
        let mut previous = head;
        for &entry in entries {
            // SAFETY: LIST_ENTRY da cabeça ou de uma entrada.
            unsafe { ListEntry::at(previous) }.flink.set(entry);
            // SAFETY: LIST_ENTRY no início do ARBITER_LIST_ENTRY.
            unsafe { ListEntry::at(entry) }.blink.set(previous);
            previous = entry;
        }
        // SAFETY: idem.
        unsafe { ListEntry::at(previous) }.flink.set(head);
        // SAFETY: cabeça alocada acima.
        unsafe { ListEntry::at(head) }.blink.set(previous);
        // SAFETY: ARBITER_PARAMETERS zerado: ArbitrationList em +0 nas
        // variantes Test, Retest, QueryArbitrate e BootAllocation.
        unsafe { ArbiterParameters::at(parameters) }.parameters.test_allocation.arbitration_list.set(head);
    }
    let parameter_block = if list.is_some() { parameters } else { 0 };
    let status = native_call::call(arbiter.arbiter_handler.get(), &[arbiter.context.get(), action, parameter_block]) as i32;
    guest::free_bytes(head);
    guest::free_bytes(parameters);
    status
}

/// IopTranslateAndAdjustReqDesc: cada alternativa do requisito pelo
/// TranslateResourceRequirements do tradutor; o requisito novo junta as
/// saídas. Devolve também se o tradutor completou a tradução.
fn translate_requirement(translator: u64, descriptors: Descriptors, pdo: u64) -> Result<(Descriptors, bool), i32> {
    // SAFETY: TRANSLATOR_INTERFACE entregue pela pilha.
    let interface = unsafe { TranslatorInterface::at(translator) };
    let mut output: Vec<u8> = Vec::new();
    let mut complete = false;
    let count_cell = guest::alloc_bytes(8);
    let target_cell = guest::alloc_bytes(8);
    for index in 0..descriptors.count {
        guest::write32(count_cell, 0);
        guest::write64(target_cell, 0);
        let status = native_call::call(interface.translate_resource_requirements.get(), &[interface.interface.context.get(), descriptors.at(index), pdo, count_cell, target_cell]) as i32;
        if status < 0 {
            guest::free_bytes(count_cell);
            guest::free_bytes(target_cell);
            return Err(status);
        }
        complete |= status == STATUS_TRANSLATION_COMPLETE;
        let (count, target) = (guest::read32(count_cell), guest::read64(target_cell));
        if target != 0 {
            output.extend(guest::read_bytes(target, count as usize * IoResourceDescriptor::SIZE as usize));
            let _ = crate::ntos::ex::pool_allocation::free(target, 0);
        }
    }
    guest::free_bytes(count_cell);
    guest::free_bytes(target_cell);
    let count = (output.len() / IoResourceDescriptor::SIZE as usize) as u32;
    let address = guest::alloc_bytes(output.len().max(1) as u64);
    guest::write_bytes(address, &output);
    for index in 0..count {
        // SAFETY: descritor copiado acima.
        let descriptor = unsafe { IoResourceDescriptor::at(address + index as u64 * IoResourceDescriptor::SIZE) };
        descriptor.option.set(if index == 0 { descriptor.option.get() & !IO_RESOURCE_ALTERNATIVE } else { descriptor.option.get() | IO_RESOURCE_ALTERNATIVE });
    }
    Ok((Descriptors { address, count }, complete))
}

/// TranslateResources de um tradutor sobre um recurso.
fn translate_resource(translator: u64, source: &Resource, direction: u64, alternatives: Option<Descriptors>, pdo: u64) -> Result<(Resource, bool), i32> {
    // SAFETY: TRANSLATOR_INTERFACE entregue pela pilha.
    let interface = unsafe { TranslatorInterface::at(translator) };
    let source_address = guest::alloc_bytes(CmPartialResourceDescriptor::SIZE);
    let target_address = guest::alloc_bytes(CmPartialResourceDescriptor::SIZE);
    resources::write_partial(source_address, source);
    let (count, list) = alternatives.map_or((0, 0), |descriptors| (descriptors.count as u64, descriptors.address));
    let status = native_call::call(interface.translate_resources.get(), &[interface.interface.context.get(), source_address, direction, count, list, pdo, target_address]) as i32;
    let result = resources::read_partial(target_address);
    guest::free_bytes(source_address);
    guest::free_bytes(target_address);
    if status < 0 {
        return Err(status);
    }
    Ok((result, status == STATUS_TRANSLATION_COMPLETE))
}

/// Quem arbitra e quem traduz um requisito de `pdo`.
struct Route {
    /// O ARBITER_INTERFACE do driver; None = os árbitros da raiz.
    arbiter: Option<u64>,
    /// Os tradutores do nó até a raiz, na ordem da subida.
    translators: Vec<u64>,
    /// Os tradutores abaixo do árbitro, que traduziram o requisito, com as
    /// alternativas que cada um recebeu.
    below: Vec<(u64, Descriptors)>,
    /// O requisito como o árbitro o recebe.
    descriptors: Descriptors,
}

impl Route {
    fn free(self) {
        for (_, descriptors) in self.below {
            descriptors.free();
        }
        self.descriptors.free();
    }
}

/// IopSetupArbiterAndTranslators para um requisito (`need`, as opções do
/// mesmo tipo) de `pdo`.
fn setup(pdo: u64, header: &Requirements, need: &[Choice]) -> Result<Route, KernelError> {
    let resource = need[0].resource_type;
    let root = devnode::root();
    let mut route = Route { arbiter: None, translators: Vec::new(), below: Vec::new(), descriptors: Descriptors::copy_of(need) };
    let mut search_translators = true;
    let mut node = pdo;
    while node != 0 && node != root {
        if route.arbiter.is_none() && node != pdo {
            let interface = query_handler(Kind::Arbiter, node, resource)?;
            // SAFETY: ARBITER_INTERFACE guardado.
            if interface != 0 && unsafe { ArbiterInterface::at(interface) }.flags.get() & ARBITER_PARTIAL != 0 {
                let entry = new_entry(pdo, header, route.descriptors);
                let status = call_arbiter(interface, action::QUERY_ARBITRATE, &[entry]);
                guest::free_bytes(entry);
                if status >= 0 {
                    route.arbiter = Some(interface);
                }
            } else if interface != 0 {
                route.arbiter = Some(interface);
            }
        }
        if search_translators {
            let translator = query_handler(Kind::Translator, node, resource)?;
            if translator != 0 {
                route.translators.push(translator);
                if route.arbiter.is_none() {
                    match translate_requirement(translator, route.descriptors, pdo) {
                        Ok((translated, complete)) => {
                            route.below.push((translator, route.descriptors));
                            route.descriptors = translated;
                            search_translators = !complete;
                        }
                        Err(status) => {
                            route.free();
                            return Err(KernelError::new(alloc::format!("TranslateResourceRequirements -> {:#x}", status as u32)));
                        }
                    }
                }
            }
        }
        node = devnode::get(node).map_or(0, |current| current.parent);
    }
    Ok(route)
}

/// O recurso bruto (espaço do dispositivo) e o traduzido (espaço da raiz)
/// de uma atribuição no espaço do árbitro.
fn raw_and_translated(route: &Route, assigned: Resource, pdo: u64) -> Result<(Resource, Resource), i32> {
    // IopParentToRawTranslation: de volta pelos tradutores abaixo do árbitro.
    let mut raw = assigned;
    for (translator, alternatives) in route.below.iter().rev() {
        raw = translate_resource(*translator, &raw, TRANSLATE_PARENT_TO_CHILD, Some(*alternatives), pdo)?.0;
    }
    // IopChildToRootTranslation.
    let mut translated = raw;
    let mut complete = false;
    for &translator in &route.translators {
        let (next, done) = translate_resource(translator, &translated, TRANSLATE_CHILD_TO_PARENT, None, pdo)?;
        translated = next;
        if done {
            complete = true;
            break;
        }
    }
    if !complete {
        translated = resources::translate_at_root(&translated);
    } else if raw.resource_type == resource_type::INTERRUPT && raw.flags & CM_RESOURCE_INTERRUPT_MESSAGE == 0 {
        crate::hal::interrupt_lines::route_vector(translated.length, raw.length);
    }
    Ok((raw, translated))
}

/// Tenta uma lista alternativa: as listas bruta e traduzida, ou None.
fn try_alternative(pdo: u64, header: &Requirements, needs: &[Vec<Choice>]) -> Result<Option<(CmList, CmList)>, KernelError> {
    let mut routes: Vec<Option<Route>> = Vec::new();
    let mut failed = false;
    for need in needs {
        match need[0].resource_type {
            resource_type::DEVICE_PRIVATE => routes.push(None),
            _ => match setup(pdo, header, need) {
                Ok(route) => routes.push(Some(route)),
                Err(error) => {
                    debug_print!("[pnp] arbitro/tradutor do tipo {}: {}", need[0].resource_type, error);
                    failed = true;
                    break;
                }
            },
        }
    }
    let free_routes = |routes: Vec<Option<Route>>| routes.into_iter().flatten().for_each(Route::free);
    if failed {
        free_routes(routes);
        return Ok(None);
    }
    // Os árbitros da raiz.
    let mut assigned: Vec<Option<Resource>> = alloc::vec![None; needs.len()];
    let mut at_root: Vec<Resource> = Vec::new();
    for (index, route) in routes.iter().enumerate() {
        match route {
            None => assigned[index] = needs[index].first().and_then(|choice| resources::place_at_root(pdo, choice, &[])),
            Some(route) if route.arbiter.is_none() => {
                let placed = choices_of(route.descriptors).iter().find_map(|choice| resources::place_at_root(pdo, choice, &at_root));
                match placed {
                    Some(resource) => {
                        at_root.push(resource);
                        assigned[index] = Some(resource);
                    }
                    None => {
                        free_routes(routes);
                        return Ok(None);
                    }
                }
            }
            Some(_) => {}
        }
    }
    // Os árbitros dos drivers: as entradas de cada um numa lista.
    let mut groups: Vec<(u64, Vec<(usize, u64)>)> = Vec::new();
    for (index, route) in routes.iter().enumerate() {
        let Some(Route { arbiter: Some(interface), descriptors, .. }) = route else { continue };
        let entry = new_entry(pdo, header, *descriptors);
        match groups.iter_mut().find(|(candidate, _)| candidate == interface) {
            Some((_, entries)) => entries.push((index, entry)),
            None => groups.push((*interface, alloc::vec![(index, entry)])),
        }
    }
    let free_groups = |groups: &[(u64, Vec<(usize, u64)>)]| groups.iter().flat_map(|(_, entries)| entries.iter()).for_each(|&(_, entry)| guest::free_bytes(entry));
    let mut accepted: Vec<u64> = Vec::new();
    for (interface, entries) in &groups {
        let list: Vec<u64> = entries.iter().map(|&(_, entry)| entry).collect();
        let status = call_arbiter(*interface, action::TEST_ALLOCATION, &list);
        if status < 0 {
            debug_print!("[pnp] {}: TestAllocation de {:#x} -> {:#x}", devnode::get(pdo).map(|node| node.instance_path).unwrap_or_default(), interface, status as u32);
            for &tested in &accepted {
                call_arbiter(tested, action::ROLLBACK_ALLOCATION, &[]);
            }
            free_groups(&groups);
            free_routes(routes);
            return Ok(None);
        }
        accepted.push(*interface);
    }
    for (interface, entries) in &groups {
        for &(index, entry) in entries {
            // O árbitro preencheu o Assignment no TestAllocation (o da
            // biblioteca de árbitros não toca no Result de um pedido
            // atendido; um pedido nulo volta ArbiterResultNullRequest).
            // SAFETY: entrada preenchida pelo árbitro no TestAllocation.
            let fields = unsafe { ArbiterListEntry::at(entry) };
            let result = fields.result.get();
            if result != ArbiterResult::ARBITER_RESULT_NULL_REQUEST && result != ArbiterResult::ARBITER_RESULT_EXTERNAL_CONFLICT {
                assigned[index] = Some(resources::read_partial(fields.assignment.get()));
            }
        }
        let status = call_arbiter(*interface, action::COMMIT_ALLOCATION, &[]);
        if status < 0 {
            debug_print!("[pnp] CommitAllocation de {:#x} -> {:#x}", interface, status as u32);
        }
    }
    free_groups(&groups);
    // Os recursos da raiz ficam registrados; os árbitros dos drivers, guardados.
    resources::release(pdo);
    resources::reserve(pdo, &CmList { interface_type: header.interface_type, bus_number: header.bus_number, resources: at_root });
    HELD.lock().insert(pdo, accepted);
    let mut raw = CmList { interface_type: header.interface_type, bus_number: header.bus_number, resources: Vec::new() };
    let mut translated = raw.clone();
    for (index, route) in routes.iter().enumerate() {
        let Some(resource) = assigned[index] else { continue };
        match route {
            None => {
                raw.resources.push(resource);
                translated.resources.push(resource);
            }
            Some(route) => match raw_and_translated(route, resource, pdo) {
                Ok((device, system)) => {
                    raw.resources.push(device);
                    translated.resources.push(system);
                }
                Err(status) => {
                    debug_print!("[pnp] traducao do recurso {:x?} -> {:#x}", resource, status as u32);
                    free_routes(routes);
                    release(pdo);
                    return Ok(None);
                }
            },
        }
    }
    free_routes(routes);
    Ok(Some((raw, translated)))
}

/// PnpAllocateResources de um nó: as listas bruta e traduzida da primeira
/// lista alternativa que todos os árbitros aceitam, ou None (conflito).
pub fn allocate(pdo: u64, requirements: &Requirements) -> Result<Option<(CmList, CmList)>, KernelError> {
    for alternative in requirements.alternatives.iter().filter(|alternative| !alternative.is_empty()) {
        if let Some(lists) = try_alternative(pdo, requirements, alternative)? {
            return Ok(Some(lists));
        }
    }
    Ok(None)
}

/// IopReleaseResources: os árbitros dos drivers recebem um pedido nulo do
/// PDO (TestAllocation sem alternativas e CommitAllocation), e a raiz
/// esquece as faixas dele.
pub fn release(pdo: u64) {
    let held = HELD.lock().remove(&pdo).unwrap_or_default();
    let empty = Requirements::default();
    for interface in held {
        let entry = new_entry(pdo, &empty, Descriptors { address: 0, count: 0 });
        if call_arbiter(interface, action::TEST_ALLOCATION, &[entry]) >= 0 {
            call_arbiter(interface, action::COMMIT_ALLOCATION, &[]);
        }
        guest::free_bytes(entry);
    }
    resources::release(pdo);
}

/// Grava a resposta de uma pilha (o árbitro, `arbiter`, ou o tradutor do
/// tipo; 0 = nenhum) como se o nó tivesse sido perguntado.
pub fn remember(pdo: u64, arbiter: bool, resource: u8, interface: u64) {
    let kind = if arbiter { Kind::Arbiter } else { Kind::Translator };
    HANDLERS.lock().insert((pdo, kind, resource), interface);
}

/// Esquece as respostas de tratadores de um nó removido.
pub fn forget(pdo: u64) {
    HANDLERS.lock().retain(|&(node, _, _), _| node != pdo);
}
