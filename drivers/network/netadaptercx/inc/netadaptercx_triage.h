/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Triage block the debugger reads to walk NetAdapterCx devices
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#define NETADAPTERCX_TRIAGE_SIGNATURE 0x9ADCBFE0
#define NETADAPTERCX_TRIAGE_VERSION_3 3

typedef struct _NETADAPTERCX_GLOBAL_TRIAGE_BLOCK
{
    ULONG Signature;
    USHORT Version;
    USHORT Size;
    USHORT StateMachineEngineOffset;
    USHORT NxDeviceAdapterCollectionOffset;
    USHORT NxAdapterCollectionCountOffset;
    USHORT NxAdapterLinkageOffset;
    ULONG64 ResetDiagnosticsStartAddr;
    ULONG64 ResetDiagnosticsSize;
    USHORT NxAdapterNxNdisMiniportOffset;
    USHORT NxNdisMiniportHandleOffset;
} NETADAPTERCX_GLOBAL_TRIAGE_BLOCK;

C_ASSERT(sizeof(NETADAPTERCX_GLOBAL_TRIAGE_BLOCK) == 40);
C_ASSERT(FIELD_OFFSET(NETADAPTERCX_GLOBAL_TRIAGE_BLOCK, ResetDiagnosticsStartAddr) == 0x10);
C_ASSERT(FIELD_OFFSET(NETADAPTERCX_GLOBAL_TRIAGE_BLOCK, NxNdisMiniportHandleOffset) == 0x22);

extern NETADAPTERCX_GLOBAL_TRIAGE_BLOCK g_NetAdapterCxTriageBlock;
