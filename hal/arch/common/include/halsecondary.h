/*
 * PROJECT:     OpenNT Hardware Abstraction Layer
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Secondary (GPIO) interrupt controller services shared by the HALs
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif.ing@outlook.com>
 */

#pragma once

#define HALP_SECONDARY_GSIV_COUNT 512

ULONG HalpSecondaryArchGsivBase(VOID);
ULONG HalpSecondaryArchVectorBase(VOID);

BOOLEAN HalpSecondaryIsIntId(_In_ ULONG IntId);
ULONG HalpSecondaryTranslateGsi(_In_ ULONG Gsi);
KIRQL HalpSecondaryIrql(_In_ ULONG IntId);
BOOLEAN HalpSecondaryEnable(_In_ ULONG IntId, _In_ KINTERRUPT_MODE InterruptMode);
VOID HalpSecondaryDisable(_In_ ULONG IntId);
VOID HalpSecondaryInitializeDispatch(VOID);
NTSTATUS HalpSecondaryRegisterInterface(_In_ ULONG BufferSize, _In_ PVOID Buffer);
NTSTATUS HalpSecondaryQueryInformation(_In_ ULONG BufferSize, _Out_ PVOID Buffer, _Out_opt_ PULONG ReturnedLength);
