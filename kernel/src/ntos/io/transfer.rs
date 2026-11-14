//! Pacotes de conclusão e transferência de arquivos para o convidado.
//!
//! - `completion_packets` — mini-pacotes de conclusão
//! - `backed_file_transfer` — transferência de arquivos com armazenamento

/// Pacotes de conclusão com armazenamento real; o cache limitado conserva
/// blocos livres e devolve a quota ao dono antes de permitir o reuso.
pub mod completion_packets {
    use alloc::vec::Vec;

    use crate::ntos::ex::pool_allocation;
    use crate::hal::amd64::native_call;
    use crate::ntos::mm::kernel_pool;
    use crate::rtl::{KernelError, SpinLock};
    use crate::ntos::inc::types::{IoMiniCompletionPacketUser, NtStruct};

    /// Pacote de conclusão (o layout do IO_MINI_COMPLETION_PACKET_USER; os
    /// de kernel têm só os 0x38 primeiros bytes).
    pub fn packet_at(pointer: u64) -> &'static IoMiniCompletionPacketUser {
        // SAFETY: pacote vivo deste cache, de uma IOCP ou fornecido pelo dono.
        unsafe { IoMiniCompletionPacketUser::at(pointer) }
    }

    /// PacketType: 1 (pool), 3 (pool com cota) e 4 (pacote de usuário).
    const PACKET_POOL: u32 = 1;
    const PACKET_QUOTA: u32 = 3;
    const PACKET_USER: u32 = 4;

    pub const PACKET_BYTE_LENGTH: u64 = 0x38;
    pub const USER_PACKET_BYTE_LENGTH: u64 = 0x50;
    pub const PACKET_TAG: u32 = 0x2070_6349;
    pub const CACHE_CAPACITY: usize = 16;

    static CACHED: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());

    /// Um bloco do cache não é cobrado de novo; sem memória ou quota o
    /// helper original devolve NULL (flag 8 do mesmo alocador).
    pub fn allocate(charge_quota: bool) -> u64 {
        if let Some(pointer) = CACHED.lock().pop() {
            packet_at(pointer).packet_type.set(PACKET_POOL);
            return pointer;
        }
        let pointer = if charge_quota {
            crate::ntos::ex::pool_quota::allocate(0x208, PACKET_BYTE_LENGTH, PACKET_TAG).unwrap_or(0)
        } else {
            pool_allocation::allocate_tagged(0x200, PACKET_BYTE_LENGTH, PACKET_TAG).unwrap_or(0)
        };
        if pointer != 0 {
            packet_at(pointer).packet_type.set(if charge_quota { PACKET_QUOTA } else { PACKET_POOL });
        }
        pointer
    }

    /// A retirada transfere a posse ao callback de um pacote de usuário; sem
    /// callback, Allocated decide se o pool recebe o bloco de volta.
    pub fn release(pointer: u64) -> Result<(), KernelError> {
        if CACHED.lock().contains(&pointer) {
            return Err(KernelError::new("completion packet released twice"));
        }
        let packet = packet_at(pointer);
        let packet_type = packet.packet_type.get();
        if packet_type == PACKET_USER {
            let callback = packet.mini_packet_callback.get();
            if callback != 0 {
                native_call::call(callback, &[pointer, packet.context.get()]);
            } else if packet.allocated.get() != 0 {
                kernel_pool::free(pointer, None)?;
            }
            return Ok(());
        }
        if packet_type != PACKET_POOL && packet_type != PACKET_QUOTA {
            return Err(KernelError::new("invalid mini completion packet type"));
        }
        let owned = kernel_pool::info(pointer).is_some_and(|allocation| !allocation.paged && allocation.bytes >= PACKET_BYTE_LENGTH);
        if !owned {
            return Err(KernelError::new("completion packet has no nonpaged pool owner"));
        }
        let room = CACHED.lock().len() < CACHE_CAPACITY;
        if room {
            kernel_pool::return_quota(pointer)?;
            CACHED.lock().push(pointer);
        } else {
            kernel_pool::free(pointer, None)?;
        }
        Ok(())
    }

    /// Libera só blocos ociosos; pacotes em filas ou callbacks têm donos.
    pub fn trim() {
        loop {
            let Some(pointer) = CACHED.lock().pop() else { return };
            let _ = kernel_pool::free(pointer, None);
        }
    }

    pub fn cached_count() -> usize {
        CACHED.lock().len()
    }

    /// IoInitializeMiniCompletionPacket(Packet, Callback, Context) (ntoskrnl
    /// 19041 rva 0x8943b0): o pacote de usuário (PacketType 4) do chamador,
    /// com a rotina chamada na retirada (Packet, Context) e Allocated =
    /// FALSE; os demais campos ficam como o chamador os deixou.
    pub fn initialize_mini(packet: &IoMiniCompletionPacketUser, callback: u64, context: u64) {
        packet.packet_type.set(PACKET_USER);
        packet.mini_packet_callback.set(callback);
        packet.context.set(context);
        packet.allocated.set(0);
    }

    /// IoAllocateMiniCompletionPacket(Callback, Context) (ntoskrnl 19041 rva
    /// 0x7023f0, sobre o IopAllocateMiniCompletionPacket do tipo 4): um
    /// pacote de usuário de 0x50 bytes do NonPagedPoolNx ('Icp '), com a
    /// rotina, o contexto e Allocated = TRUE; sem memória, NULL.
    pub fn allocate_mini(callback: u64, context: u64) -> u64 {
        let pointer = pool_allocation::allocate_priority(0x200, USER_PACKET_BYTE_LENGTH, PACKET_TAG, 0).unwrap_or(0);
        if pointer != 0 {
            let packet = packet_at(pointer);
            packet.packet_type.set(PACKET_USER);
            packet.mini_packet_callback.set(callback);
            packet.context.set(context);
            packet.allocated.set(1);
        }
        pointer
    }

    /// IoFreeMiniCompletionPacket(Packet) (rva 0x65cb10): sem a rotina, o
    /// IopFreeMiniCompletionPacket devolve ao pool o pacote alocado.
    pub fn free_mini(pointer: u64) -> Result<(), KernelError> {
        packet_at(pointer).mini_packet_callback.set(0);
        release(pointer)
    }

    pub fn is_cached(pointer: u64) -> bool {
        CACHED.lock().contains(&pointer)
    }
}

/// Transfere arquivos para o buffer do chamador sem outra cópia inteira:
/// cada bloco mantém só suas páginas residentes, e os erros reais vão ao
/// serviço de leitura (dono do IOSB, do evento e da APC).
pub mod backed_file_transfer {
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use crate::drivers::fs::ntfs::Ntfs;
    use crate::ntos::mm::io_pins;
    use alloc::string::String;

    use crate::rtl::KernelError;
    use crate::ntos::mm::guest_memory as guest;

    const TRANSFER_BLOCK_BYTES: u64 = 64 * 1024;
    const PAGE_BYTES: u64 = 4096;
    const PHYSICAL_COPY_LIMIT: u64 = 0x1_0000_0000;

    /// Fonte dos bytes do arquivo.
    pub trait TransferSource {
        /// `None` = o provedor não devolveu dados.
        fn read_at(&self, offset: u64, length: u64) -> Result<Option<Vec<u8>>, KernelError>;
        /// Provedores com cópia física direta (DMA) para a memória do convidado.
        fn supports_copy_to_physical(&self) -> bool {
            false
        }
        /// Copia a faixa inteira ou falha (só chamado quando suportado).
        fn copy_to_physical(&self, _offset: u64, _physical: u64, _length: u64) -> Result<(), KernelError> {
            Err(KernelError::new("filesystem has no physical copy"))
        }
    }

    /// Arquivo de um volume NTFS montado.
    pub struct NtfsFile {
        pub volume: Arc<Ntfs>,
        pub path: String,
    }

    impl TransferSource for NtfsFile {
        fn read_at(&self, offset: u64, length: u64) -> Result<Option<Vec<u8>>, KernelError> {
            self.volume.read_range(&self.path, offset, length)
        }
        fn supports_copy_to_physical(&self) -> bool {
            true
        }
        fn copy_to_physical(&self, offset: u64, physical: u64, length: u64) -> Result<(), KernelError> {
            self.volume.copy_range_to_physical(&self.path, offset, physical, length)
        }
    }

    /// Provedor sem cópia física: uma leitura curta encerra a transferência,
    /// nunca preenchida com zeros.
    fn copy_buffered_range(source: &dyn TransferSource, offset: u64, output: u64, requested: u64) -> Result<u64, KernelError> {
        let Some(bytes) = source.read_at(offset, requested)? else {
            return Err(KernelError::with_status("filesystem read returned no data", 0xC000_0185));
        };
        if bytes.len() as u64 > requested {
            return Err(KernelError::new("filesystem read exceeded request"));
        }
        guest::write_bytes(output, &bytes);
        Ok(bytes.len() as u64)
    }

    /// Traduz e fixa as páginas atuais com escrita; só junta PFNs fisicamente
    /// contíguos. Destinos acima de 4 GiB usam a escrita virtual.
    fn copy_pinned_range(source: &dyn TransferSource, offset: u64, output: u64, requested: u64) -> Result<u64, KernelError> {
        let mut residency = io_pins::pin(output, requested, true)?;
        let result = (|| {
            let mut copied = 0u64;
            let mut page = 0usize;
            while copied < requested {
                let virtual_address = output + copied;
                let page_offset = virtual_address & 4095;
                let physical = residency.pages[page].frame + page_offset;
                let mut span = (PAGE_BYTES - page_offset).min(requested - copied);
                page += 1;
                while copied + span < requested && page < residency.pages.len() && residency.pages[page].frame == physical + span {
                    span += PAGE_BYTES.min(requested - copied - span);
                    page += 1;
                }
                let transferred = if physical + span <= PHYSICAL_COPY_LIMIT {
                    // O contrato do provedor é copiar a faixa inteira ou falhar.
                    source.copy_to_physical(offset + copied, physical, span)?;
                    span
                } else {
                    copy_buffered_range(source, offset + copied, virtual_address, span)?
                };
                copied += transferred;
                if transferred < span {
                    break;
                }
            }
            Ok(copied)
        })();
        // Inclusive em falhas de disco, sem deixar páginas presas.
        residency.release()?;
        result
    }

    /// A conclusão pública ocorre uma vez, depois de todos os blocos reais.
    pub fn read_into_guest(source: &dyn TransferSource, offset: u64, output: u64, requested: u64) -> Result<u64, KernelError> {
        let physical = source.supports_copy_to_physical();
        let mut copied = 0u64;
        while copied < requested {
            let block = TRANSFER_BLOCK_BYTES.min(requested - copied);
            let destination = output + copied;
            let transferred = if physical { copy_pinned_range(source, offset + copied, destination, block)? } else { copy_buffered_range(source, offset + copied, destination, block)? };
            copied += transferred;
            if transferred < block {
                break;
            }
        }
        Ok(copied)
    }
}
