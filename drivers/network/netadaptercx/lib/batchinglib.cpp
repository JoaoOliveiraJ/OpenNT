/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Batching of buffer copy and checksum operations
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#include <ntosp.h>
#include <batchinglib.h>
#include "batchinglibp.h"

C_ASSERT(sizeof(BL_LIB_CONTEXT) <= sizeof(BATCHING_LIB_CONTEXT));
C_ASSERT(sizeof(BL_BUFFER_CONTEXT) <= sizeof(BATCHING_BUFFER_CONTEXT));

_Use_decl_annotations_
VOID
BLInitialize(
    BATCHING_LIB_CONTEXT * LibContext)
{
    RtlZeroMemory(LibContext, sizeof(*LibContext));

    auto context = reinterpret_cast<BL_LIB_CONTEXT *>(LibContext);
    context->Signature = BL_LIB_CONTEXT_SIGNATURE;
}

_Use_decl_annotations_
VOID
BLUninitialize(
    BATCHING_LIB_CONTEXT * LibContext)
{
    auto context = reinterpret_cast<BL_LIB_CONTEXT *>(LibContext);

    if (context->Signature == BL_LIB_CONTEXT_SIGNATURE)
    {
        context->Signature = 0;
    }
}

_Use_decl_annotations_
VOID
BLInitializeBatchOpContext(
    BATCHING_LIB_CONTEXT * LibContext,
    BATCHING_BUFFER_CONTEXT * BufferContext,
    BOOLEAN DispatchLevel,
    BOOLEAN DependsOnContext,
    BATCHING_BUFFER_CONTEXT * DependencyContext)
{
    UNREFERENCED_PARAMETER(DependsOnContext);
    UNREFERENCED_PARAMETER(DependencyContext);

    auto libContext = reinterpret_cast<BL_LIB_CONTEXT *>(LibContext);
    NT_ASSERT(libContext->Signature == BL_LIB_CONTEXT_SIGNATURE);

    RtlZeroMemory(BufferContext, sizeof(*BufferContext));

    auto context = reinterpret_cast<BL_BUFFER_CONTEXT *>(BufferContext);
    context->Signature = BL_BUFFER_CONTEXT_SIGNATURE;
    context->DispatchLevel = DispatchLevel;
    context->LibContext = libContext;
}

_Use_decl_annotations_
VOID
BLFlushBatchOpContext(
    BATCHING_BUFFER_CONTEXT * BufferContext)
{
    auto context = reinterpret_cast<BL_BUFFER_CONTEXT *>(BufferContext);
    NT_ASSERT(context->Signature == BL_BUFFER_CONTEXT_SIGNATURE);

    context->Signature = 0;
}
