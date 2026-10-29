/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Software checksum, large send and UDP segmentation offloads
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#include <batchinglib.h>

#define SEGLIB_OFFLOAD_PERFORM_NONE 0x00000000
#define SEGLIB_OFFLOAD_PERFORM_CSO 0x00000001
#define SEGLIB_OFFLOAD_PERFORM_LSO 0x00000002
#define SEGLIB_OFFLOAD_PERFORM_USO 0x00000004

#define SEGLIB_OFFLOAD_OVERRIDE_INFO_SEGMENT_SET 0x0001
#define SEGLIB_OFFLOAD_OVERRIDE_INFO_CSO_SET 0x0002

typedef struct _SEGLIB_CONTEXT
{
    ULONG64 Reserved[4];
} SEGLIB_CONTEXT;

C_ASSERT(sizeof(SEGLIB_CONTEXT) == 32);

typedef enum _SEGLIB_NBL_DIRECTION
{
    TxtoTx = 0,
    RxtoRx = 1,
    TxtoRx = 2,
    RxtoTx = 3,
} SEGLIB_NBL_DIRECTION;

typedef struct _SEGLIB_CHKSUM_OFFLOAD_INFO
{
    USHORT TransportHeaderOffset;
    BOOLEAN IsIPv6;
    BOOLEAN PerformChecksumOffload;
} SEGLIB_CHKSUM_OFFLOAD_INFO;

typedef struct _SEGLIB_OFFLOAD_INFO
{
    union
    {
        NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO LsoInfo;
        NDIS_UDP_SEGMENTATION_OFFLOAD_NET_BUFFER_LIST_INFO UsoInfo;
    };
    USHORT PartChecksum;
    BOOLEAN UseOriginalChecksum;
} SEGLIB_OFFLOAD_INFO;

typedef struct _SEGLIB_OFFLOAD_OVERRIDE_INFO
{
    USHORT OffloadDataSet;
    SEGLIB_OFFLOAD_INFO SegmentOffloadInfo;
    SEGLIB_CHKSUM_OFFLOAD_INFO ChecksumOffloadInfo;
    SEGLIB_NBL_DIRECTION NblDirection;
} SEGLIB_OFFLOAD_OVERRIDE_INFO;

C_ASSERT(sizeof(SEGLIB_CHKSUM_OFFLOAD_INFO) == 4);
C_ASSERT(sizeof(SEGLIB_OFFLOAD_INFO) == 16);
C_ASSERT(sizeof(SEGLIB_OFFLOAD_OVERRIDE_INFO) == 32);
C_ASSERT(FIELD_OFFSET(SEGLIB_OFFLOAD_OVERRIDE_INFO, ChecksumOffloadInfo) == 0x18);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
SegLibInitialize(
    _In_ BATCHING_LIB_CONTEXT * BatchingLibContext,
    _Out_ SEGLIB_CONTEXT * Context);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
SegLibUninitialize(
    _Inout_ SEGLIB_CONTEXT * Context);

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
SegLibDeferredChecksumPacket(
    _Inout_ BATCHING_BUFFER_CONTEXT * BufferContext,
    _Inout_ NET_BUFFER * NetBuffer,
    _In_ NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO ChecksumInfo,
    _In_ UCHAR IpHeaderOffset,
    _In_ USHORT TransportHeaderOffset,
    _In_ BOOLEAN IsIPv6);

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
SegLibCreateMultiNbNblClone(
    _In_ SEGLIB_CONTEXT * Context,
    _In_ NET_BUFFER_LIST * NetBufferList,
    _In_ BOOLEAN IsReceive,
    _In_ UCHAR IpHeaderOffset,
    _In_opt_ SEGLIB_OFFLOAD_OVERRIDE_INFO * OverrideInfo,
    _In_opt_ NDIS_HANDLE NetBufferListPool,
    _In_opt_ NDIS_HANDLE NetBufferPool,
    _In_ USHORT NetBufferListContextSize,
    _In_ ULONG DataBackFill,
    _Out_ NET_BUFFER_LIST ** CloneNetBufferList,
    _Out_ ULONG * DataOffset,
    _Out_ ULONG * OffloadsPerformed);

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
SegLibCreateMultiNbNblUsoClone(
    _In_ SEGLIB_CONTEXT * Context,
    _In_ NET_BUFFER_LIST * NetBufferList,
    _In_ BOOLEAN IsReceive,
    _In_ UCHAR IpHeaderOffset,
    _In_opt_ SEGLIB_OFFLOAD_OVERRIDE_INFO * OverrideInfo,
    _In_opt_ NDIS_HANDLE NetBufferListPool,
    _In_opt_ NDIS_HANDLE NetBufferPool,
    _In_ USHORT NetBufferListContextSize,
    _In_ ULONG DataBackFill,
    _Out_ NET_BUFFER_LIST ** CloneNetBufferList,
    _Out_ ULONG * DataOffset,
    _Out_ ULONG * OffloadsPerformed);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
SegLibFreeMultiNbNblClone(
    _In_ NET_BUFFER_LIST * CloneNetBufferList,
    _In_ ULONG DataOffset);
