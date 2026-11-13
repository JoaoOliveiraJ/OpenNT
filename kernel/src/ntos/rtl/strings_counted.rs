//! Strings contadas do Rtl — `system32/ntos/rtl/{append-unicode-string,copy-unicode-string,initialize-ansi-string}.js`.

use crate::ntos::mm::guest_memory as guest;

const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const MAXIMUM_SOURCE_CHARACTERS: u64 = 0x7FFE;
const MAXIMUM_ANSI_LENGTH: u64 = 0xFFFE;

/// memmove byte a byte: a direção inversa preserva a origem sobreposta.
fn move_bytes(destination: u64, source: u64, length: u64) {
    let backwards = destination > source && destination < source + length;
    for index in 0..length {
        let offset = if backwards { length - index - 1 } else { index };
        guest::write8(destination + offset, guest::read8(source + offset));
    }
}

/// RtlAppendUnicodeToString: concatena uma origem WCHAR terminada em NUL.
pub fn append(destination: u64, source: u64) -> u32 {
    // Origem NULL retorna sem consultar o descritor de destino.
    if source == 0 {
        return 0;
    }
    // O NUL é procurado antes de rejeitar o tamanho; só o contador satura.
    let mut cursor = source;
    let mut count = 0u64;
    while guest::read16(cursor) != 0 {
        if count <= MAXIMUM_SOURCE_CHARACTERS {
            count += 1;
        }
        cursor = cursor.wrapping_add(2);
    }
    if count > MAXIMUM_SOURCE_CHARACTERS {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let length = guest::read16(destination) as u64;
    let appended = count * 2;
    if length + appended > guest::read16(destination + 2) as u64 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let at = guest::read64(destination + 8) + (length & !1);
    move_bytes(at, source, appended);
    // Soma ao Length presente depois da cópia (o buffer pode sobrepor o descritor).
    guest::write16(destination, (guest::read16(destination) as u64 + appended) as u16);
    if (guest::read16(destination) as u32) + 1 < guest::read16(destination + 2) as u32 {
        guest::write16(at + appended, 0);
    }
    0
}

/// RtlCopyUnicodeString: copia por bytes (inclusive comprimento ímpar).
pub fn copy(destination: u64, source: u64) {
    if source == 0 {
        guest::write16(destination, 0);
        return;
    }
    let copied = (guest::read16(source)).min(guest::read16(destination + 2)) as u64;
    let source_buffer = guest::read64(source + 8);
    let destination_buffer = guest::read64(destination + 8);
    guest::write16(destination, copied as u16);
    move_bytes(destination_buffer, source_buffer, copied);
    // NUL só com dois bytes extras; o índice WCHAR descarta o bit ímpar.
    if guest::read16(destination) as u32 + 2 <= guest::read16(destination + 2) as u32 {
        guest::write16(destination_buffer + (copied & !1), 0);
    }
}

/// RtlInitAnsiString: descritor escrito antes de procurar o terminador.
pub fn initialize_ansi(destination: u64, source: u64) {
    guest::write64(destination, 0);
    guest::write64(destination + 8, source);
    if source == 0 {
        return;
    }
    let mut cursor = source;
    let mut length = 0u64;
    while guest::read8(cursor) != 0 {
        if length < MAXIMUM_ANSI_LENGTH {
            length += 1;
        }
        cursor = cursor.wrapping_add(1);
    }
    guest::write16(destination, length as u16);
    guest::write16(destination + 2, (length + 1) as u16);
}
