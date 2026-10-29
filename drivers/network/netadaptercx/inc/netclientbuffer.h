/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Buffer pool interface between NetAdapterCx and its datapath client
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#include <netclienttypes.h>

typedef struct _NET_DATA_HEADER
{
    UINT64 LogicalAddress;
    void * KmVirtualAddress;
    void * UmVirtualAddress;
    PMDL Mdl;
    UINT32 Index;
} NET_DATA_HEADER;

typedef enum _NET_CLIENT_BUFFER_POOL_FLAGS
{
    NET_CLIENT_BUFFER_POOL_FLAGS_NONE = 0x00000000,
    NET_CLIENT_BUFFER_POOL_FLAGS_SERIALIZATION = 0x00000001,
} NET_CLIENT_BUFFER_POOL_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(NET_CLIENT_BUFFER_POOL_FLAGS);

typedef struct _NET_CLIENT_BUFFER_POOL_CONFIG
{
    NET_CLIENT_MEMORY_CONSTRAINTS * MemoryConstraints;
    SIZE_T BufferCount;
    SIZE_T BufferSize;
    SIZE_T BufferAlignmentOffset;
    SIZE_T BufferAlignment;
    ULONG PreferredNode;
    NET_CLIENT_BUFFER_POOL_FLAGS Flag;
    PEPROCESS Process;
} NET_CLIENT_BUFFER_POOL_CONFIG;

typedef
void
(*ENUMERATE_CALLBACK)(
    _In_ void * Context,
    _In_ NET_DATA_HEADER * NetDataHeader);

typedef
_IRQL_requires_(PASSIVE_LEVEL)
void
NET_CLIENT_DESTROY_BUFFER_POOL(
    _In_ NET_CLIENT_BUFFER_POOL Pool);

typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
NET_CLIENT_ENUMERATE_BUFFERS(
    _In_ NET_CLIENT_BUFFER_POOL Pool,
    _In_ ENUMERATE_CALLBACK Callback,
    _In_ void * Context);

typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
NET_CLIENT_ALLOCATE_BUFFER(
    _In_ NET_CLIENT_BUFFER_POOL Pool,
    _Out_ SIZE_T * Index,
    _Out_ NET_DATA_HEADER * NetDataHeader,
    _Out_ SIZE_T * NetDataOffset);

typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
NET_CLIENT_FREE_BUFFERS(
    _In_ NET_CLIENT_BUFFER_POOL Pool,
    _Inout_updates_(NumBuffers) SIZE_T * Buffers,
    _In_ ULONG NumBuffers);

typedef struct _NET_CLIENT_BUFFER_POOL_DISPATCH
{
    ULONG Size;
    NET_CLIENT_DESTROY_BUFFER_POOL * NetClientDestroyBufferPool;
    NET_CLIENT_ENUMERATE_BUFFERS * NetClientEnumerateBuffers;
    NET_CLIENT_ALLOCATE_BUFFER * NetClientAllocateBuffer;
    NET_CLIENT_FREE_BUFFERS * NetClientFreeBuffers;
} NET_CLIENT_BUFFER_POOL_DISPATCH;

typedef
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NET_CLIENT_CREATE_BUFFER_POOL(
    _In_ NET_CLIENT_BUFFER_POOL_CONFIG * BufferPoolConfig,
    _Out_ NET_CLIENT_BUFFER_POOL * Pool,
    _Out_ NET_CLIENT_BUFFER_POOL_DISPATCH const ** BufferPoolDispatch);
