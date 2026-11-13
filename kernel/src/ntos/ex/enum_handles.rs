//! ExEnumHandleTable.
//!
//! Percorre a HANDLE_TABLE nativa do chamador. O callback recebe a entrada
//! bloqueada e libera esse bloqueio antes de retornar.

use crate::hal::amd64::native_call;
use crate::ntos::ke::{critical_region, dispatcher, irql};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

/// Descarta os bits de atributo, verifica o limite da tabela e percorre
/// zero, um ou dois níveis de páginas até a entrada de 16 bytes.
pub fn lookup(table: u64, handle: u64) -> u64 {
    let handle = handle & !3;
    if handle >= guest::read32(table) as u64 {
        return 0;
    }
    let code = guest::read64(table + 8);
    match code & 3 {
        0 => code + handle * 4,
        1 => guest::read64(code - 1 + (handle >> 10) * 8) + (handle & 1023) * 4,
        _ => {
            let directory = guest::read64(code - 2 + (handle >> 19) * 8);
            guest::read64(directory + ((handle >> 10) & 511) * 8) + (handle & 1023) * 4
        }
    }
}

/// Próximo passo da enumeração.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Entrada ocupada: aguardar desbloqueio ou exclusão.
    Busy,
    /// Executar `callback(table, entry, handle, context)` com a entrada bloqueada.
    Callback { callback: u64, arguments: [u64; 4] },
    /// BOOLEAN final.
    Done(u8),
}

/// Enumeração suspensível dentro de uma região crítica.
pub struct EnumRequest {
    table: u64,
    callback: u64,
    context: u64,
    output_handle: u64,
    handle: u64,
    entry: u64,
    pending: bool,
    locked_value: u64,
    active: bool,
    result: u8,
}

pub fn begin(table: u64, callback: u64, context: u64, output_handle: u64) -> Result<EnumRequest, KernelError> {
    if irql::get_irql() >= 2 {
        return Err(KernelError::new("ExEnumHandleTable requires IRQL below DISPATCH_LEVEL"));
    }
    critical_region::enter_critical()?;
    // O cursor começa depois da entrada reservada.
    let entry = lookup(table, 4);
    Ok(EnumRequest { table, callback, context, output_handle, handle: 4, entry, pending: false, locked_value: 0, active: true, result: 0 })
}

impl EnumRequest {
    /// Sai da região crítica uma única vez.
    fn finish(&mut self) {
        if self.active {
            self.active = false;
            let _ = critical_region::leave_critical();
        }
    }

    /// Quatro unidades por handle, saltando a primeira entrada reservada de
    /// cada folha.
    fn advance(&mut self) {
        let next = self.handle + 4;
        if (next ^ self.handle) >= 1024 {
            self.handle = next + 4;
            self.entry = lookup(self.table, self.handle);
        } else {
            self.handle = next;
            self.entry += 16;
        }
    }

    pub fn poll(&mut self) -> Result<Step, KernelError> {
        if !self.active {
            return Ok(Step::Done(self.result));
        }
        if self.pending {
            return Err(KernelError::new("handle enumeration callback still running"));
        }
        while self.entry != 0 {
            let low = guest::compare_exchange64(self.entry, 0, 0)?;
            if low == 0 {
                self.advance();
                continue;
            }
            // Entrada ocupada: a própria palavra revela desbloqueio ou exclusão.
            if low & 1 == 0 {
                return Ok(Step::Busy);
            }
            if guest::compare_exchange64(self.entry, low, low - 1)? != low {
                continue;
            }
            // O callback passa a possuir o bloqueio da entrada.
            self.pending = true;
            self.locked_value = low - 1;
            return Ok(Step::Callback { callback: self.callback, arguments: [self.table, self.entry, self.handle, self.context] });
        }
        self.finish();
        Ok(Step::Done(self.result))
    }

    /// O byte baixo do retorno decide se a enumeração para; uma resposta não
    /// nula publica o handle encontrado.
    pub fn resume(&mut self, value: u64) -> Result<(), KernelError> {
        if !self.pending {
            return Err(KernelError::new("handle enumeration has no pending callback"));
        }
        self.pending = false;
        self.result = value as u8;
        if self.result != 0 {
            if self.output_handle != 0 {
                guest::write64(self.output_handle, self.handle);
            }
            self.finish();
        } else {
            self.advance();
        }
        Ok(())
    }

    /// Nenhum callback executou: libera só o bloqueio adquirido para ele.
    pub fn callback_failed(&mut self) {
        if self.pending {
            let _ = guest::compare_exchange64(self.entry, self.locked_value, self.locked_value + 1);
            self.pending = false;
        }
        self.finish();
    }

    pub fn cancel(&mut self) {
        self.finish();
    }
}

impl Drop for EnumRequest {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Conduz a enumeração até o fim, executando o callback pela ABI nativa.
pub fn enumerate(table: u64, callback: u64, context: u64, output_handle: u64) -> Result<u8, KernelError> {
    let mut request = begin(table, callback, context, output_handle)?;
    loop {
        match request.poll()? {
            Step::Busy => dispatcher::pump_kernel(),
            Step::Done(result) => return Ok(result),
            Step::Callback { callback, arguments } => {
                let value = native_call::call(callback, &arguments);
                request.resume(value)?;
            }
        }
    }
}
