/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     NBL queue helpers (Microsoft NDIS Driver Library) used by NetAdapterCx
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#include <ndis.h>
#include <ndis/ndl/nblqueue.h>

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
void
NdisAppendNblChainWithTailPointerToNblCountedQueueFast(
    _Inout_ NBL_COUNTED_QUEUE * CountedQueue,
    _In_ NET_BUFFER_LIST * NblChainFirst,
    _In_ NET_BUFFER_LIST ** NblChainTailPointer,
    _In_ SIZE_T NumNblsToAppend)
{
    *CountedQueue->Queue.Last = NblChainFirst;
    CountedQueue->Queue.Last = NblChainTailPointer;
    CountedQueue->NblCount += NumNblsToAppend;
}
