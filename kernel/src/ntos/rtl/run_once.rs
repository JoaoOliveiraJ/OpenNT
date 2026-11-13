//! RTL_RUN_ONCE.
//!
//! Bits baixos: 0 inicial, 1 inicialização síncrona (os bits altos apontam
//! a pilha de esperadores), 2 contexto concluído, 3 inicialização
//! assíncrona. Bloco de espera de 0x30 bytes: Next +0, KTHREAD +0x18,
//! Flags +0x24 (bit 4 = liberado).

use crate::hal::amd64::native_call;
use crate::ntos::ke::{critical_region, dispatcher, irql};
use crate::ntos::ps::process;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const PENDING: u32 = 0x103;
const UNSUCCESSFUL: u32 = 0xC000_0001;
const BAD_FLAGS: u32 = 0xC000_00F0;
const BAD_CONTEXT: u32 = 0xC000_00F1;

fn exchange(pointer: u64, previous: u64, updated: u64) -> Result<bool, KernelError> {
    Ok(guest::compare_exchange64(pointer, previous, updated)? == previous)
}

fn require_passive_or_apc() -> Result<(), KernelError> {
    if irql::get_irql() > 1 {
        return Err(KernelError::new("RTL_RUN_ONCE requires IRQL <= APC_LEVEL"));
    }
    Ok(())
}

/// RtlRunOnceInitialize.
pub fn initialize(pointer: u64) -> Result<u32, KernelError> {
    require_passive_or_apc()?;
    guest::write64(pointer, 0);
    Ok(0)
}

/// Disputa por CAS, contexto já publicado ou bloco de espera síncrona.
pub struct BeginRequest {
    pointer: u64,
    flags: u32,
    context: u64,
    wait_block: u64,
    result: Option<u32>,
}

impl BeginRequest {
    /// `None` enquanto espera a conclusão de outro inicializador.
    pub fn poll(&mut self) -> Result<Option<u32>, KernelError> {
        if let Some(result) = self.result {
            return Ok(Some(result));
        }
        if self.flags > 2 {
            return Ok(Some(BAD_FLAGS));
        }
        // O esperador só libera o próprio bloco depois do bit 4 publicado.
        if self.wait_block != 0 {
            if guest::read32(self.wait_block + 0x24) & 4 == 0 {
                return Ok(None);
            }
            guest::free_bytes(self.wait_block);
            self.wait_block = 0;
        }
        loop {
            let word = guest::read64(self.pointer);
            let state = word & 3;
            let finish = |request: &mut Self, status: u32| {
                request.result = Some(status);
                Ok(Some(status))
            };
            if state == 2 {
                if self.context != 0 {
                    guest::write64(self.context, word & !3);
                }
                return finish(self, 0);
            }
            if self.flags == 1 {
                return finish(self, UNSUCCESSFUL);
            }
            if state == 0 {
                if exchange(self.pointer, word, if self.flags == 2 { 3 } else { 1 })? {
                    return finish(self, PENDING);
                }
                continue;
            }
            if state == 3 {
                return finish(self, if self.flags == 2 { PENDING } else { BAD_FLAGS });
            }
            if self.flags == 2 {
                return finish(self, BAD_FLAGS);
            }
            // Bloco zerado com a thread atual ligado ao topo; CAS perdido tenta de novo.
            let block = guest::alloc_bytes(0x30);
            if block == 0 {
                return Err(KernelError::new("RTL_RUN_ONCE wait block allocation failed"));
            }
            for offset in (0..0x30).step_by(8) {
                guest::write64(block + offset, 0);
            }
            guest::write64(block + 0x18, process::get_current_thread());
            guest::write64(block, word & !3);
            if exchange(self.pointer, word, block | 1)? {
                self.wait_block = block;
                return Ok(None);
            }
            guest::free_bytes(block);
        }
    }
}

pub fn begin(pointer: u64, flags: u32, context: u64) -> Result<BeginRequest, KernelError> {
    require_passive_or_apc()?;
    Ok(BeginRequest { pointer, flags, context, wait_block: 0, result: None })
}

/// RtlRunOnceBeginInitialize: consulta até haver resultado.
pub fn begin_initialize(pointer: u64, flags: u32, context: u64) -> Result<u32, KernelError> {
    let mut request = begin(pointer, flags, context)?;
    loop {
        if let Some(result) = request.poll()? {
            return Ok(result);
        }
        dispatcher::pump_kernel();
    }
}

/// RtlRunOnceComplete: publica conclusão (ou volta ao inicial com
/// RTL_RUN_ONCE_INIT_FAILED) e libera os esperadores depois do CAS.
pub fn complete(pointer: u64, flags: u32, context: u64) -> Result<u32, KernelError> {
    require_passive_or_apc()?;
    if flags != 0 && flags != 2 && flags != 4 {
        return Ok(BAD_FLAGS);
    }
    if context & 3 != 0 || (flags == 4 && context != 0) {
        return Ok(BAD_CONTEXT);
    }
    let updated = if flags == 4 { 0 } else { context | 2 };
    loop {
        let previous = guest::read64(pointer);
        let state = previous & 3;
        if state != 1 && state != 3 {
            return Ok(UNSUCCESSFUL);
        }
        if (state == 3) != (flags == 2) {
            return Ok(BAD_FLAGS);
        }
        // Corrida perdida: colisão no assíncrono; no síncrono pode ser um novo esperador.
        if !exchange(pointer, previous, updated)? {
            if flags == 2 {
                return Ok(0xC000_0035);
            }
            continue;
        }
        if state == 1 {
            let mut block = previous & !3;
            while block != 0 {
                // Next é lido antes de liberar: o acordado pode liberar o bloco já.
                let next = guest::read64(block);
                loop {
                    let current = guest::read32(block + 0x24);
                    if guest::compare_exchange32(block + 0x24, current, current | 4)? == current {
                        break;
                    }
                }
                block = next;
            }
        }
        return Ok(0);
    }
}

/// Passo de uma execução: resultado final ou chamada ao inicializador nativo.
pub enum ExecutionStep {
    Done(u32),
    Callback { routine: u64, arguments: [u64; 3] },
}

/// Requisição de RtlRunOnceExecuteOnce: a região crítica cobre a aquisição
/// e a execução do inicializador e sai uma única vez.
pub struct ExecutionRequest {
    pointer: u64,
    routine: u64,
    parameter: u64,
    context: u64,
    begin: BeginRequest,
    released: bool,
    dispatched: bool,
    result: Option<u32>,
}

impl ExecutionRequest {
    fn finish(&mut self, status: u32) -> u32 {
        if !self.released {
            self.released = true;
            let _ = critical_region::leave_critical();
        }
        self.result = Some(status);
        status
    }

    pub fn poll(&mut self) -> Result<Option<ExecutionStep>, KernelError> {
        if let Some(result) = self.result {
            return Ok(Some(ExecutionStep::Done(result)));
        }
        if self.dispatched {
            return Err(KernelError::new("RTL_RUN_ONCE callback has not returned"));
        }
        let status = match self.begin.poll() {
            Ok(status) => status,
            Err(error) => {
                self.finish(UNSUCCESSFUL);
                return Err(error);
            }
        };
        let Some(status) = status else { return Ok(None) };
        if status != PENDING {
            return Ok(Some(ExecutionStep::Done(self.finish(status))));
        }
        self.dispatched = true;
        Ok(Some(ExecutionStep::Callback { routine: self.routine, arguments: [self.pointer, self.parameter, self.context] }))
    }

    /// Retorno do inicializador em 32 bits; falha reinicia o estado e um
    /// contexto inválido vira erro, nunca conclusão.
    pub fn resume(&mut self, value: u64) -> Result<(), KernelError> {
        let succeeded = value & 0xFFFF_FFFF != 0;
        let status = complete(self.pointer, if succeeded { 0 } else { 4 }, if succeeded && self.context != 0 { guest::read64(self.context) } else { 0 })?;
        self.finish(if status != 0 { status } else if succeeded { 0 } else { UNSUCCESSFUL });
        if status != 0 {
            return Err(KernelError::with_status(alloc::format!("RtlRunOnceExecuteOnce invalid completion 0x{status:x}"), status));
        }
        Ok(())
    }
}

pub fn execute_request(pointer: u64, routine: u64, parameter: u64, context: u64) -> Result<ExecutionRequest, KernelError> {
    require_passive_or_apc()?;
    critical_region::enter_critical()?;
    let begin = match begin(pointer, 0, context) {
        Ok(begin) => begin,
        Err(error) => {
            let _ = critical_region::leave_critical();
            return Err(error);
        }
    };
    Ok(ExecutionRequest { pointer, routine, parameter, context, begin, released: false, dispatched: false, result: None })
}

/// RtlRunOnceExecuteOnce síncrono: o inicializador é chamado pela ABI real.
pub fn execute(pointer: u64, routine: u64, parameter: u64, context: u64) -> Result<u32, KernelError> {
    let mut request = execute_request(pointer, routine, parameter, context)?;
    let step = loop {
        match request.poll()? {
            Some(step) => break step,
            None => dispatcher::pump_kernel(),
        }
    };
    match step {
        ExecutionStep::Done(status) => Ok(status),
        ExecutionStep::Callback { routine, arguments } => {
            let value = native_call::call(routine, &arguments);
            request.resume(value)?;
            match request.poll()? {
                Some(ExecutionStep::Done(status)) => Ok(status),
                _ => Err(KernelError::new("RTL_RUN_ONCE request did not finish")),
            }
        }
    }
}
