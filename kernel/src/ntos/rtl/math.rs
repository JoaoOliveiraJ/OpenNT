//! Aritmética da runtime — a `sqrt` da CRT (soft-float, sobre os bits
//! IEEE-754) e o gerador congruente do RtlRandom/RtlRandomEx.
//!
//! O kernel é soft-float (sem SSE): a raiz sai de aritmética inteira e o
//! argumento/resultado em XMM0 passa pelo slot do CONTEXT capturado.

use crate::ntos::inc::types::{Context, Field, NtStruct};

/// RtlRandom/RtlRandomEx: o LCG documentado; atualiza a semente e devolve
/// 15 bits.
pub fn random(seed_address: u64) -> u32 {
    // SAFETY: PULONG Seed do chamador (o NT também não o trata como interlocked).
    let cell = unsafe { Field::<u32>::at(seed_address) };
    let seed = cell.get().wrapping_mul(214_013).wrapping_add(2_531_011);
    cell.set(seed);
    (seed >> 16) & 0x7FFF
}


/// sqrt(double): argumento e resultado em XMM0. Lê/grava o slot XMM0 do
/// CONTEXT capturado (CONTEXT+0x1A0, dentro do FXSAVE), pois o trampolim
/// comum faz FXRSTOR64 na volta — assim o resultado chega ao chamador. Sem
/// CONTEXT (chamada interna) não há nada a fazer.
pub fn sqrt_in_context(context: u64) {
    if context == 0 {
        return;
    }
    // SAFETY: CONTEXT capturado pelo gateway nativo.
    let xmm0 = &unsafe { Context::at(context) }.flt_save.xmm_registers[0];
    xmm0.low.set(sqrt_bits(xmm0.low.get()));
}

/// Piso da raiz de um u128 por Newton. O palpite inicial 2^ceil(bits/2) é
/// sempre >= a raiz, então a sequência decresce até o piso.
fn isqrt_u128(value: u128) -> u128 {
    if value < 2 {
        return value;
    }
    let bits = 128 - value.leading_zeros();
    let mut guess: u128 = 1u128 << bits.div_ceil(2);
    loop {
        let next = (guess + value / guess) >> 1;
        if next >= guess {
            return guess;
        }
        guess = next;
    }
}

/// sqrt de binary64 com arredondamento ao mais próximo, como o `sqrtsd`:
/// ±0 -> ±0, +inf -> +inf, NaN -> NaN silenciado, negativo ou -inf -> o NaN
/// "indefinido" 0xFFF8_0000_0000_0000. Subnormais são normalizados antes.
pub fn sqrt_bits(bits: u64) -> u64 {
    const INDEFINITE_NAN: u64 = 0xFFF8_0000_0000_0000;
    let negative = bits >> 63 != 0;
    let exponent = ((bits >> 52) & 0x7FF) as i64;
    let fraction = bits & ((1u64 << 52) - 1);
    if exponent == 0x7FF {
        if fraction != 0 {
            return bits | (1u64 << 51);
        }
        return if negative { INDEFINITE_NAN } else { bits };
    }
    if exponent == 0 && fraction == 0 {
        return bits;
    }
    if negative {
        return INDEFINITE_NAN;
    }
    // valor = mantissa * 2^(power - 52), com a mantissa em [2^52, 2^53).
    let (mut mantissa, mut power) = if exponent == 0 {
        let shift = fraction.leading_zeros() as i64 - 11;
        (fraction << shift, -1022 - shift)
    } else {
        (fraction | (1u64 << 52), exponent - 1023)
    };
    // Expoente par: sqrt(valor) = sqrt(mantissa << 52) * 2^(power/2 - 52).
    if power & 1 != 0 {
        mantissa <<= 1;
        power -= 1;
    }
    let wide = (mantissa as u128) << 52;
    let mut root = isqrt_u128(wide);
    // Arredonda para cima quando sqrt(wide) > root + 1/2 (empate exato
    // é impossível para a raiz de um inteiro).
    if wide - root * root > root {
        root += 1;
    }
    let mut half = power / 2;
    if root == 1u128 << 53 {
        root >>= 1;
        half += 1;
    }
    (((half + 1023) as u64) << 52) | (root as u64 & ((1u64 << 52) - 1))
}

/// sqrtf(float) pela tabela de exports: o export público é o corpo nativo
/// (`sqrtss xmm0, xmm0`, em `hal/amd64/private_entries`); quem entra pelo
/// trampolim tem o argumento e o resultado no slot XMM0 do CONTEXT, como o
/// `sqrt`.
pub fn sqrtf_in_context(context: u64) {
    if context == 0 {
        return;
    }
    // SAFETY: CONTEXT capturado pelo gateway nativo.
    let xmm0 = &unsafe { Context::at(context) }.flt_save.xmm_registers[0];
    let low = xmm0.low.get();
    xmm0.low.set((low & !0xFFFF_FFFF) | sqrtf_bits(low as u32) as u64);
}

/// sqrt de binary32 com arredondamento ao mais próximo, como o `sqrtss`:
/// ±0 -> ±0, +inf -> +inf, NaN -> NaN silenciado, negativo ou -inf -> o NaN
/// "indefinido" 0xFFC0_0000. Subnormais são normalizados antes.
pub fn sqrtf_bits(bits: u32) -> u32 {
    const INDEFINITE_NAN: u32 = 0xFFC0_0000;
    let negative = bits >> 31 != 0;
    let exponent = ((bits >> 23) & 0xFF) as i32;
    let fraction = bits & ((1u32 << 23) - 1);
    if exponent == 0xFF {
        if fraction != 0 {
            return bits | (1u32 << 22);
        }
        return if negative { INDEFINITE_NAN } else { bits };
    }
    if exponent == 0 && fraction == 0 {
        return bits;
    }
    if negative {
        return INDEFINITE_NAN;
    }
    // valor = mantissa * 2^(power - 23), com a mantissa em [2^23, 2^24).
    let (mut mantissa, mut power) = if exponent == 0 {
        let shift = fraction.leading_zeros() as i32 - 8;
        (fraction << shift, -126 - shift)
    } else {
        (fraction | (1u32 << 23), exponent - 127)
    };
    if power & 1 != 0 {
        mantissa <<= 1;
        power -= 1;
    }
    let wide = (mantissa as u128) << 23;
    let mut root = isqrt_u128(wide);
    if wide - root * root > root {
        root += 1;
    }
    let mut half = power / 2;
    if root == 1u128 << 24 {
        root >>= 1;
        half += 1;
    }
    (((half + 127) as u32) << 23) | (root as u32 & ((1u32 << 23) - 1))
}
