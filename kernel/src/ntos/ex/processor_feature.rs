//! Recursos do processador vistos pelo Executive (ExIsProcessorFeaturePresent).
//!
//! No ntoskrnl 19041 (0x32afe0) a rotina só lê o vetor que o kernel publica
//! na KUSER_SHARED_DATA: `Feature < PROCESSOR_FEATURE_MAX (64)` devolve o
//! byte ProcessorFeatures[Feature]; acima disso, FALSE. É o mesmo vetor que o
//! IsProcessorFeaturePresent do modo usuário consulta.

use crate::ntos::mm::shared_user_data;

/// PROCESSOR_FEATURE_MAX.
const PROCESSOR_FEATURE_MAX: u32 = 64;

/// ExIsProcessorFeaturePresent(ProcessorFeature): o byte publicado.
pub fn is_present(feature: u32) -> u8 {
    if feature >= PROCESSOR_FEATURE_MAX {
        return 0;
    }
    shared_user_data::data().map_or(0, |data| data.processor_features[feature as usize].get())
}
