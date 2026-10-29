/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Software receive segment coalescing
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#include <ntosp.h>
#include <rsclib.h>

struct RSCLIB_CONTEXT_INTERNAL
{
    void const * ClientCookie;
    RSCLIB_STATS Stats;
};

C_ASSERT(sizeof(RSCLIB_CONTEXT_INTERNAL) <= sizeof(RSCLIB_SERIAL_COALESCING_CONTEXT));

_Use_decl_annotations_
VOID
RSCLIBInitializeContext(
    void const * ClientCookie,
    RSCLIB_SERIAL_COALESCING_CONTEXT * Context)
{
    RtlZeroMemory(Context, sizeof(*Context));

    auto context = reinterpret_cast<RSCLIB_CONTEXT_INTERNAL *>(Context);
    context->ClientCookie = ClientCookie;
}

_Use_decl_annotations_
VOID
RSCLIBReadAndResetStats(
    RSCLIB_SERIAL_COALESCING_CONTEXT * Context,
    RSCLIB_STATS * Stats)
{
    auto context = reinterpret_cast<RSCLIB_CONTEXT_INTERNAL *>(Context);

    *Stats = context->Stats;
    RtlZeroMemory(&context->Stats, sizeof(context->Stats));
}

_Use_decl_annotations_
VOID
RSCLIBCoalesceNBL(
    RSCLIB_SERIAL_COALESCING_CONTEXT * Context,
    UCHAR IpHeaderOffset,
    UCHAR Flags,
    USHORT Reserved,
    NET_BUFFER_LIST * NetBufferList,
    NET_BUFFER_LIST *** TailOfNblChain,
    ULONG * NumberOfNbls)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(IpHeaderOffset);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(Reserved);

    /* TODO: coalesce in-order TCP and UDP segments of one flow into single coalesced units */
    NetBufferList->Next = nullptr;
    **TailOfNblChain = NetBufferList;
    *TailOfNblChain = &NetBufferList->Next;
    ++*NumberOfNbls;
}

_Use_decl_annotations_
VOID
RSCLIBFlushContext(
    RSCLIB_SERIAL_COALESCING_CONTEXT * Context,
    NET_BUFFER_LIST *** TailOfNblChain,
    ULONG * NumberOfNbls)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(TailOfNblChain);
    UNREFERENCED_PARAMETER(NumberOfNbls);
}

_Use_decl_annotations_
BOOLEAN
RscLibExUtilMatchCoalescedNBLCookie(
    NET_BUFFER_LIST const * NetBufferList,
    void const * ClientCookie)
{
    UNREFERENCED_PARAMETER(NetBufferList);
    UNREFERENCED_PARAMETER(ClientCookie);

    return FALSE;
}

_Use_decl_annotations_
VOID
RscLibExUncoalesceNBL(
    NET_BUFFER_LIST * NetBufferList,
    void const * ClientCookie,
    NET_BUFFER_LIST ** LastNetBufferList,
    ULONG * NumberOfNbls)
{
    UNREFERENCED_PARAMETER(ClientCookie);

    *LastNetBufferList = NetBufferList;
    *NumberOfNbls = 1;
}
