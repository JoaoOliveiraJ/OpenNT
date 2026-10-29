/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Software receive segment coalescing
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#define RSCLIB_FLAG_ALLOW_DEFERRED_CHECKSUM 0x01
#define RSCLIB_FLAG_SKIP_TCP 0x02
#define RSCLIB_FLAG_SKIP_UDP 0x04

typedef struct _RSCLIB_STATS
{
    USHORT CoalescedSegments;
    USHORT GeneratedSCUs;
    ULONG CoalescedTransportPayloadBytes;
} RSCLIB_STATS;

typedef struct _RSCLIB_SERIAL_COALESCING_CONTEXT
{
    ULONG64 Reserved[47];
} RSCLIB_SERIAL_COALESCING_CONTEXT;

C_ASSERT(sizeof(RSCLIB_STATS) == 8);
C_ASSERT(sizeof(RSCLIB_SERIAL_COALESCING_CONTEXT) == 376);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RSCLIBInitializeContext(
    _In_ void const * ClientCookie,
    _Out_ RSCLIB_SERIAL_COALESCING_CONTEXT * Context);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RSCLIBReadAndResetStats(
    _Inout_ RSCLIB_SERIAL_COALESCING_CONTEXT * Context,
    _Out_ RSCLIB_STATS * Stats);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RSCLIBCoalesceNBL(
    _Inout_ RSCLIB_SERIAL_COALESCING_CONTEXT * Context,
    _In_ UCHAR IpHeaderOffset,
    _In_ UCHAR Flags,
    _In_ USHORT Reserved,
    _In_ NET_BUFFER_LIST * NetBufferList,
    _Inout_ NET_BUFFER_LIST *** TailOfNblChain,
    _Inout_ ULONG * NumberOfNbls);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RSCLIBFlushContext(
    _Inout_ RSCLIB_SERIAL_COALESCING_CONTEXT * Context,
    _Inout_ NET_BUFFER_LIST *** TailOfNblChain,
    _Inout_ ULONG * NumberOfNbls);

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
RscLibExUtilMatchCoalescedNBLCookie(
    _In_ NET_BUFFER_LIST const * NetBufferList,
    _In_ void const * ClientCookie);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RscLibExUncoalesceNBL(
    _In_ NET_BUFFER_LIST * NetBufferList,
    _In_ void const * ClientCookie,
    _Out_ NET_BUFFER_LIST ** LastNetBufferList,
    _Out_ ULONG * NumberOfNbls);
