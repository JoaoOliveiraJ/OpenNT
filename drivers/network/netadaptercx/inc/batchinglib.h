/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Batching of buffer copy and checksum operations
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

typedef struct _BATCHING_LIB_CONTEXT
{
    ULONG64 Reserved[32];
} BATCHING_LIB_CONTEXT;

typedef struct _BATCHING_BUFFER_CONTEXT
{
    ULONG64 Reserved[12];
} BATCHING_BUFFER_CONTEXT;

C_ASSERT(sizeof(BATCHING_LIB_CONTEXT) == 256);
C_ASSERT(sizeof(BATCHING_BUFFER_CONTEXT) == 96);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
BLInitialize(
    _Out_ BATCHING_LIB_CONTEXT * LibContext);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
BLUninitialize(
    _Inout_ BATCHING_LIB_CONTEXT * LibContext);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
BLInitializeBatchOpContext(
    _In_ BATCHING_LIB_CONTEXT * LibContext,
    _Out_ BATCHING_BUFFER_CONTEXT * BufferContext,
    _In_ BOOLEAN DispatchLevel,
    _In_ BOOLEAN DependsOnContext,
    _In_opt_ BATCHING_BUFFER_CONTEXT * DependencyContext);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
BLFlushBatchOpContext(
    _Inout_ BATCHING_BUFFER_CONTEXT * BufferContext);
