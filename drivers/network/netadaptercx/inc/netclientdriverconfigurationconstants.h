/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Driver configuration knobs NetAdapterCx reads from its service registry keys
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

typedef enum DRIVER_CONFIG_ENUM
{
    ALLOW_DMA_HAL_BYPASS = 0,
    DMA_BOUNCE_POLICY = 1,
    IGNORE_VERIFIER_DEBUG_BREAK = 2,
} DRIVER_CONFIG_ENUM;

#define ALLOW_DMA_HAL_BYPASS_NAME L"AllowDmaHalBypass"
#define DMA_BOUNCE_POLICY_NAME L"DmaBouncePolicy"
#define IGNORE_VERIFIER_DEBUG_BREAK_NAME L"IgnoreVerifierDebugBreak"

#define DRIVER_CONFIG_KNOB_IS_BOOLEAN 0x00000001
