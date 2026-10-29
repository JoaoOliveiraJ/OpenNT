/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Software checksum, large send and UDP segmentation offloads
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#include <ntosp.h>
#include <seglib.h>
#include "batchinglibp.h"

#define SEGLIB_POOL_TAG 'gSxN'

#define IPV4_VERSION 4
#define IPV6_VERSION 6
#define IPV6_HEADER_LENGTH 40
#define TCP_MINIMUM_HEADER_LENGTH 20
#define UDP_HEADER_LENGTH 8
#define IPPROTO_TCP_VALUE 6
#define IPPROTO_UDP_VALUE 17

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_CWR 0x80

struct SEGLIB_CONTEXT_INTERNAL
{
    BOOLEAN Initialized;
    BATCHING_LIB_CONTEXT * BatchingLibContext;
    NDIS_HANDLE NetBufferListPool;
    NDIS_HANDLE NetBufferPool;
};

C_ASSERT(sizeof(SEGLIB_CONTEXT_INTERNAL) <= sizeof(SEGLIB_CONTEXT));

struct CHECKSUM_ACCUMULATOR
{
    ULONG64 Sum;
    ULONG Position;
};

static
void
ChecksumAdd(
    _Inout_ CHECKSUM_ACCUMULATOR & Accumulator,
    _In_reads_bytes_(Length) UCHAR const * Data,
    _In_ ULONG Length)
{
    for (ULONG i = 0; i < Length; i++)
    {
        Accumulator.Sum += (Accumulator.Position & 1) ? Data[i] : static_cast<ULONG>(Data[i]) << 8;
        Accumulator.Position++;
    }
}

static
void
ChecksumAddWord(
    _Inout_ CHECKSUM_ACCUMULATOR & Accumulator,
    _In_ ULONG Value)
{
    Accumulator.Sum += Value;
}

static
USHORT
ChecksumFinish(
    _Inout_ CHECKSUM_ACCUMULATOR & Accumulator)
{
    while (Accumulator.Sum >> 16)
    {
        Accumulator.Sum = (Accumulator.Sum & 0xFFFF) + (Accumulator.Sum >> 16);
    }

    return static_cast<USHORT>(~Accumulator.Sum & 0xFFFF);
}

static
USHORT
ReadBigEndian16(
    _In_reads_bytes_(2) UCHAR const * Data)
{
    return static_cast<USHORT>((Data[0] << 8) | Data[1]);
}

static
ULONG
ReadBigEndian32(
    _In_reads_bytes_(4) UCHAR const * Data)
{
    return (static_cast<ULONG>(Data[0]) << 24) | (static_cast<ULONG>(Data[1]) << 16) |
           (static_cast<ULONG>(Data[2]) << 8) | Data[3];
}

static
void
WriteBigEndian16(
    _Out_writes_bytes_(2) UCHAR * Data,
    _In_ USHORT Value)
{
    Data[0] = static_cast<UCHAR>(Value >> 8);
    Data[1] = static_cast<UCHAR>(Value);
}

static
void
WriteBigEndian32(
    _Out_writes_bytes_(4) UCHAR * Data,
    _In_ ULONG Value)
{
    Data[0] = static_cast<UCHAR>(Value >> 24);
    Data[1] = static_cast<UCHAR>(Value >> 16);
    Data[2] = static_cast<UCHAR>(Value >> 8);
    Data[3] = static_cast<UCHAR>(Value);
}

template <typename Callback>
static
NTSTATUS
ForEachNetBufferChunk(
    _In_ NET_BUFFER * NetBuffer,
    _In_ ULONG Offset,
    _In_ ULONG Length,
    _In_ Callback && Function)
{
    ULONG const dataLength = NET_BUFFER_DATA_LENGTH(NetBuffer);

    if (Offset > dataLength || Length > dataLength - Offset)
    {
        return STATUS_INVALID_PARAMETER;
    }

    MDL * mdl = NET_BUFFER_CURRENT_MDL(NetBuffer);
    ULONG mdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer) + Offset;

    while (mdl != nullptr && mdlOffset >= MmGetMdlByteCount(mdl))
    {
        mdlOffset -= MmGetMdlByteCount(mdl);
        mdl = mdl->Next;
    }

    ULONG done = 0;

    while (done < Length)
    {
        if (mdl == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }

        ULONG const chunk = min(MmGetMdlByteCount(mdl) - mdlOffset, Length - done);

        if (chunk != 0)
        {
            auto address = static_cast<UCHAR *>(
                MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute));

            if (address == nullptr)
            {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            Function(address + mdlOffset, chunk, done);
            done += chunk;
        }

        mdlOffset = 0;
        mdl = mdl->Next;
    }

    return STATUS_SUCCESS;
}

static
NTSTATUS
ReadNetBuffer(
    _In_ NET_BUFFER * NetBuffer,
    _In_ ULONG Offset,
    _Out_writes_bytes_(Length) void * Destination,
    _In_ ULONG Length)
{
    auto destination = static_cast<UCHAR *>(Destination);

    return ForEachNetBufferChunk(NetBuffer, Offset, Length,
        [destination](UCHAR * Chunk, ULONG ChunkLength, ULONG Position)
        {
            RtlCopyMemory(destination + Position, Chunk, ChunkLength);
        });
}

static
NTSTATUS
WriteNetBuffer(
    _In_ NET_BUFFER * NetBuffer,
    _In_ ULONG Offset,
    _In_reads_bytes_(Length) void const * Source,
    _In_ ULONG Length)
{
    auto source = static_cast<UCHAR const *>(Source);

    return ForEachNetBufferChunk(NetBuffer, Offset, Length,
        [source](UCHAR * Chunk, ULONG ChunkLength, ULONG Position)
        {
            RtlCopyMemory(Chunk, source + Position, ChunkLength);
        });
}

static
NTSTATUS
ChecksumNetBuffer(
    _In_ NET_BUFFER * NetBuffer,
    _In_ ULONG Offset,
    _In_ ULONG Length,
    _Inout_ CHECKSUM_ACCUMULATOR & Accumulator)
{
    return ForEachNetBufferChunk(NetBuffer, Offset, Length,
        [&Accumulator](UCHAR * Chunk, ULONG ChunkLength, ULONG)
        {
            ChecksumAdd(Accumulator, Chunk, ChunkLength);
        });
}

static
void
AddPseudoHeader(
    _Inout_ CHECKSUM_ACCUMULATOR & Accumulator,
    _In_ UCHAR const * IpHeader,
    _In_ BOOLEAN IsIPv6,
    _In_ UCHAR Protocol,
    _In_ ULONG TransportLength)
{
    /* TODO: use the final destination of an IPv6 routing header in the pseudo-header */
    CHECKSUM_ACCUMULATOR addresses = {};

    if (IsIPv6)
    {
        ChecksumAdd(addresses, IpHeader + 8, 32);
    }
    else
    {
        ChecksumAdd(addresses, IpHeader + 12, 8);
    }

    ChecksumAddWord(Accumulator, static_cast<ULONG>(addresses.Sum & 0xFFFFFFFF));
    ChecksumAddWord(Accumulator, static_cast<ULONG>(addresses.Sum >> 32));
    ChecksumAddWord(Accumulator, Protocol);
    ChecksumAddWord(Accumulator, TransportLength & 0xFFFF);
    ChecksumAddWord(Accumulator, TransportLength >> 16);
}

_Use_decl_annotations_
VOID
SegLibInitialize(
    BATCHING_LIB_CONTEXT * BatchingLibContext,
    SEGLIB_CONTEXT * Context)
{
    RtlZeroMemory(Context, sizeof(*Context));

    auto context = reinterpret_cast<SEGLIB_CONTEXT_INTERNAL *>(Context);
    context->BatchingLibContext = BatchingLibContext;

    NET_BUFFER_LIST_POOL_PARAMETERS listParameters = {};
    listParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    listParameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    listParameters.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    listParameters.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    listParameters.fAllocateNetBuffer = FALSE;
    listParameters.PoolTag = SEGLIB_POOL_TAG;

    NET_BUFFER_POOL_PARAMETERS bufferParameters = {};
    bufferParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    bufferParameters.Header.Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    bufferParameters.Header.Size = NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    bufferParameters.PoolTag = SEGLIB_POOL_TAG;

    context->NetBufferListPool = NdisAllocateNetBufferListPool(nullptr, &listParameters);
    context->NetBufferPool = NdisAllocateNetBufferPool(nullptr, &bufferParameters);

    context->Initialized = context->NetBufferListPool != nullptr && context->NetBufferPool != nullptr;
}

_Use_decl_annotations_
VOID
SegLibUninitialize(
    SEGLIB_CONTEXT * Context)
{
    auto context = reinterpret_cast<SEGLIB_CONTEXT_INTERNAL *>(Context);

    if (context->NetBufferPool != nullptr)
    {
        NdisFreeNetBufferPool(context->NetBufferPool);
        context->NetBufferPool = nullptr;
    }

    if (context->NetBufferListPool != nullptr)
    {
        NdisFreeNetBufferListPool(context->NetBufferListPool);
        context->NetBufferListPool = nullptr;
    }

    context->Initialized = FALSE;
}

_Use_decl_annotations_
NTSTATUS
SegLibDeferredChecksumPacket(
    BATCHING_BUFFER_CONTEXT * BufferContext,
    NET_BUFFER * NetBuffer,
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO ChecksumInfo,
    UCHAR IpHeaderOffset,
    USHORT TransportHeaderOffset,
    BOOLEAN IsIPv6)
{
    NT_ASSERT(reinterpret_cast<BL_BUFFER_CONTEXT *>(BufferContext)->Signature == BL_BUFFER_CONTEXT_SIGNATURE);
    UNREFERENCED_PARAMETER(BufferContext);

    ULONG const dataLength = NET_BUFFER_DATA_LENGTH(NetBuffer);
    UCHAR ipHeader[IPV6_HEADER_LENGTH];
    ULONG const ipHeaderBytes = IsIPv6 ? IPV6_HEADER_LENGTH : 20;

    NTSTATUS status = ReadNetBuffer(NetBuffer, IpHeaderOffset, ipHeader, ipHeaderBytes);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if ((ipHeader[0] >> 4) != (IsIPv6 ? IPV6_VERSION : IPV4_VERSION))
    {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG ipPacketEnd;

    if (IsIPv6)
    {
        ULONG const payloadLength = ReadBigEndian16(ipHeader + 4);
        ipPacketEnd = payloadLength != 0 ? IpHeaderOffset + IPV6_HEADER_LENGTH + payloadLength : dataLength;
    }
    else
    {
        ULONG const totalLength = ReadBigEndian16(ipHeader + 2);
        ipPacketEnd = totalLength != 0 ? IpHeaderOffset + totalLength : dataLength;
    }

    if (ipPacketEnd > dataLength)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (!IsIPv6 && ChecksumInfo.Transmit.IpHeaderChecksum)
    {
        ULONG const headerLength = (ipHeader[0] & 0x0F) * 4;

        if (headerLength < 20)
        {
            return STATUS_INVALID_PARAMETER;
        }

        UCHAR const zero[2] = {};
        status = WriteNetBuffer(NetBuffer, IpHeaderOffset + 10, zero, sizeof(zero));

        if (!NT_SUCCESS(status))
        {
            return status;
        }

        CHECKSUM_ACCUMULATOR accumulator = {};
        status = ChecksumNetBuffer(NetBuffer, IpHeaderOffset, headerLength, accumulator);

        if (!NT_SUCCESS(status))
        {
            return status;
        }

        UCHAR checksum[2];
        WriteBigEndian16(checksum, ChecksumFinish(accumulator));
        status = WriteNetBuffer(NetBuffer, IpHeaderOffset + 10, checksum, sizeof(checksum));

        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }

    if (!ChecksumInfo.Transmit.TcpChecksum && !ChecksumInfo.Transmit.UdpChecksum)
    {
        return STATUS_SUCCESS;
    }

    if (TransportHeaderOffset <= IpHeaderOffset || TransportHeaderOffset > ipPacketEnd)
    {
        return STATUS_INVALID_PARAMETER;
    }

    BOOLEAN const isTcp = ChecksumInfo.Transmit.TcpChecksum;
    ULONG const checksumOffset = TransportHeaderOffset + (isTcp ? 16 : 6);
    ULONG const transportLength = ipPacketEnd - TransportHeaderOffset;

    if (transportLength < (isTcp ? TCP_MINIMUM_HEADER_LENGTH : UDP_HEADER_LENGTH))
    {
        return STATUS_INVALID_PARAMETER;
    }

    UCHAR const zero[2] = {};
    status = WriteNetBuffer(NetBuffer, checksumOffset, zero, sizeof(zero));

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    CHECKSUM_ACCUMULATOR accumulator = {};
    AddPseudoHeader(accumulator, ipHeader, IsIPv6, isTcp ? IPPROTO_TCP_VALUE : IPPROTO_UDP_VALUE, transportLength);
    status = ChecksumNetBuffer(NetBuffer, TransportHeaderOffset, transportLength, accumulator);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    USHORT value = ChecksumFinish(accumulator);

    if (!isTcp && value == 0)
    {
        value = 0xFFFF;
    }

    UCHAR checksum[2];
    WriteBigEndian16(checksum, value);
    return WriteNetBuffer(NetBuffer, checksumOffset, checksum, sizeof(checksum));
}

static
void
ChecksumSegment(
    _Inout_updates_bytes_(Length) UCHAR * Packet,
    _In_ ULONG Length,
    _In_ ULONG IpHeaderOffset,
    _In_ ULONG TransportHeaderOffset,
    _In_ BOOLEAN IsIPv6,
    _In_ BOOLEAN IsTcp)
{
    UCHAR * const ipHeader = Packet + IpHeaderOffset;

    if (!IsIPv6)
    {
        ULONG const headerLength = (ipHeader[0] & 0x0F) * 4;
        CHECKSUM_ACCUMULATOR accumulator = {};

        WriteBigEndian16(ipHeader + 10, 0);
        ChecksumAdd(accumulator, ipHeader, headerLength);
        WriteBigEndian16(ipHeader + 10, ChecksumFinish(accumulator));
    }

    UCHAR * const transportHeader = Packet + TransportHeaderOffset;
    ULONG const transportLength = Length - TransportHeaderOffset;
    UCHAR * const checksum = transportHeader + (IsTcp ? 16 : 6);
    CHECKSUM_ACCUMULATOR accumulator = {};

    WriteBigEndian16(checksum, 0);
    AddPseudoHeader(accumulator, ipHeader, IsIPv6, IsTcp ? IPPROTO_TCP_VALUE : IPPROTO_UDP_VALUE, transportLength);
    ChecksumAdd(accumulator, transportHeader, transportLength);

    USHORT value = ChecksumFinish(accumulator);

    if (!IsTcp && value == 0)
    {
        value = 0xFFFF;
    }

    WriteBigEndian16(checksum, value);
}

_Use_decl_annotations_
VOID
SegLibFreeMultiNbNblClone(
    NET_BUFFER_LIST * CloneNetBufferList,
    ULONG DataOffset)
{
    UNREFERENCED_PARAMETER(DataOffset);

    NET_BUFFER * netBuffer = NET_BUFFER_LIST_FIRST_NB(CloneNetBufferList);
    NET_BUFFER_LIST_FIRST_NB(CloneNetBufferList) = nullptr;

    while (netBuffer != nullptr)
    {
        NET_BUFFER * const next = NET_BUFFER_NEXT_NB(netBuffer);
        MDL * const mdl = NET_BUFFER_FIRST_MDL(netBuffer);

        NET_BUFFER_NEXT_NB(netBuffer) = nullptr;

        if (mdl != nullptr)
        {
            void * const buffer = MmGetMdlVirtualAddress(mdl);
            IoFreeMdl(mdl);
            ExFreePoolWithTag(buffer, SEGLIB_POOL_TAG);
        }

        NdisFreeNetBuffer(netBuffer);
        netBuffer = next;
    }

    NdisFreeNetBufferList(CloneNetBufferList);
}

static
NTSTATUS
CreateSegmentedClone(
    _In_ SEGLIB_CONTEXT * Context,
    _In_ NET_BUFFER_LIST * NetBufferList,
    _In_ BOOLEAN IsReceive,
    _In_ UCHAR IpHeaderOffset,
    _In_opt_ SEGLIB_OFFLOAD_OVERRIDE_INFO const * OverrideInfo,
    _In_opt_ NDIS_HANDLE NetBufferListPool,
    _In_opt_ NDIS_HANDLE NetBufferPool,
    _In_ USHORT NetBufferListContextSize,
    _In_ ULONG DataBackFill,
    _In_ BOOLEAN IsUdp,
    _Out_ NET_BUFFER_LIST ** CloneNetBufferList,
    _Out_ ULONG * DataOffset,
    _Out_ ULONG * OffloadsPerformed)
{
    *CloneNetBufferList = nullptr;
    *DataOffset = 0;
    *OffloadsPerformed = SEGLIB_OFFLOAD_PERFORM_NONE;

    auto context = reinterpret_cast<SEGLIB_CONTEXT_INTERNAL *>(Context);

    if (IsReceive || NetBufferListPool != nullptr || NetBufferPool != nullptr ||
        NetBufferListContextSize != 0 || DataBackFill != 0)
    {
        /* TODO: receive-direction segmentation and caller-supplied pools, context or backfill */
        return STATUS_NOT_SUPPORTED;
    }

    if (!context->Initialized)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NET_BUFFER * const source = NET_BUFFER_LIST_FIRST_NB(NetBufferList);

    if (source == nullptr || NET_BUFFER_NEXT_NB(source) != nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    BOOLEAN const overrideSegment = OverrideInfo != nullptr &&
        (OverrideInfo->OffloadDataSet & SEGLIB_OFFLOAD_OVERRIDE_INFO_SEGMENT_SET) != 0;
    ULONG mss;
    ULONG transportHeaderOffset;

    if (IsUdp)
    {
        NDIS_UDP_SEGMENTATION_OFFLOAD_NET_BUFFER_LIST_INFO info;
        info.Value = overrideSegment
            ? OverrideInfo->SegmentOffloadInfo.UsoInfo.Value
            : NET_BUFFER_LIST_INFO(NetBufferList, UdpSegmentationOffloadInfo);
        mss = info.Transmit.MSS;
        transportHeaderOffset = info.Transmit.UdpHeaderOffset;
    }
    else
    {
        NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO info;
        info.Value = overrideSegment
            ? OverrideInfo->SegmentOffloadInfo.LsoInfo.Value
            : NET_BUFFER_LIST_INFO(NetBufferList, TcpLargeSendNetBufferListInfo);
        mss = info.LsoV1Transmit.MSS;
        transportHeaderOffset = info.LsoV1Transmit.TcpHeaderOffset;
    }

    BOOLEAN const performChecksum = OverrideInfo != nullptr &&
        (OverrideInfo->OffloadDataSet & SEGLIB_OFFLOAD_OVERRIDE_INFO_CSO_SET) != 0
        ? OverrideInfo->ChecksumOffloadInfo.PerformChecksumOffload
        : TRUE;

    ULONG const dataLength = NET_BUFFER_DATA_LENGTH(source);
    UCHAR versionByte;
    NTSTATUS status = ReadNetBuffer(source, IpHeaderOffset, &versionByte, sizeof(versionByte));

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    BOOLEAN const isIPv6 = (versionByte >> 4) == IPV6_VERSION;

    if (mss == 0 || (!isIPv6 && (versionByte >> 4) != IPV4_VERSION) ||
        transportHeaderOffset <= IpHeaderOffset + (isIPv6 ? IPV6_HEADER_LENGTH - 1 : 19))
    {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG transportHeaderLength = UDP_HEADER_LENGTH;

    if (!IsUdp)
    {
        UCHAR dataOffsetByte;
        status = ReadNetBuffer(source, transportHeaderOffset + 12, &dataOffsetByte, sizeof(dataOffsetByte));

        if (!NT_SUCCESS(status))
        {
            return status;
        }

        transportHeaderLength = (dataOffsetByte >> 4) * 4;

        if (transportHeaderLength < TCP_MINIMUM_HEADER_LENGTH)
        {
            return STATUS_INVALID_PARAMETER;
        }
    }

    ULONG const headerLength = transportHeaderOffset + transportHeaderLength;

    if (headerLength > dataLength)
    {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG const payloadLength = dataLength - headerLength;
    ULONG const segmentCount = payloadLength == 0 ? 1 : (payloadLength + mss - 1) / mss;

    auto header = static_cast<UCHAR *>(ExAllocatePool2(POOL_FLAG_NON_PAGED, headerLength, SEGLIB_POOL_TAG));

    if (header == nullptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ReadNetBuffer(source, 0, header, headerLength);

    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(header, SEGLIB_POOL_TAG);
        return status;
    }

    NET_BUFFER_LIST * clone = NdisAllocateNetBufferList(context->NetBufferListPool, 0, 0);

    if (clone == nullptr)
    {
        ExFreePoolWithTag(header, SEGLIB_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NdisCopySendNetBufferListInfo(clone, NetBufferList);
    clone->ParentNetBufferList = NetBufferList;
    NET_BUFFER_LIST_INFO(clone, TcpLargeSendNetBufferListInfo) = nullptr;
#if NDIS_SUPPORT_NDIS683
    NET_BUFFER_LIST_INFO(clone, UdpSegmentationOffloadInfo) = nullptr;
#endif

    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO checksumInfo;
    checksumInfo.Value = nullptr;

    if (!performChecksum)
    {
        checksumInfo.Transmit.IsIPv4 = !isIPv6;
        checksumInfo.Transmit.IsIPv6 = isIPv6;
        checksumInfo.Transmit.TcpChecksum = !IsUdp;
        checksumInfo.Transmit.UdpChecksum = IsUdp;
        checksumInfo.Transmit.IpHeaderChecksum = !isIPv6;
        checksumInfo.Transmit.TcpHeaderOffset = transportHeaderOffset;
    }

    NET_BUFFER_LIST_INFO(clone, TcpIpChecksumNetBufferListInfo) = checksumInfo.Value;

    USHORT const ipv4Identification = isIPv6 ? 0 : ReadBigEndian16(header + IpHeaderOffset + 4);
    ULONG const tcpSequence = IsUdp ? 0 : ReadBigEndian32(header + transportHeaderOffset + 4);
    NET_BUFFER ** tail = &NET_BUFFER_LIST_FIRST_NB(clone);

    for (ULONG index = 0; index < segmentCount; index++)
    {
        ULONG const payloadOffset = index * mss;
        ULONG const segmentLength = payloadLength == 0 ? 0 : min(mss, payloadLength - payloadOffset);
        ULONG const packetLength = headerLength + segmentLength;

        auto packet = static_cast<UCHAR *>(ExAllocatePool2(POOL_FLAG_NON_PAGED, packetLength, SEGLIB_POOL_TAG));

        if (packet == nullptr)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        RtlCopyMemory(packet, header, headerLength);
        status = ReadNetBuffer(source, headerLength + payloadOffset, packet + headerLength, segmentLength);

        if (!NT_SUCCESS(status))
        {
            ExFreePoolWithTag(packet, SEGLIB_POOL_TAG);
            break;
        }

        UCHAR * const ipHeader = packet + IpHeaderOffset;
        UCHAR * const transportHeader = packet + transportHeaderOffset;

        if (isIPv6)
        {
            WriteBigEndian16(ipHeader + 4, static_cast<USHORT>(packetLength - IpHeaderOffset - IPV6_HEADER_LENGTH));
        }
        else
        {
            WriteBigEndian16(ipHeader + 2, static_cast<USHORT>(packetLength - IpHeaderOffset));
            WriteBigEndian16(ipHeader + 4, static_cast<USHORT>(ipv4Identification + index));
        }

        if (IsUdp)
        {
            WriteBigEndian16(transportHeader + 4, static_cast<USHORT>(UDP_HEADER_LENGTH + segmentLength));
        }
        else
        {
            WriteBigEndian32(transportHeader + 4, tcpSequence + payloadOffset);

            if (index + 1 != segmentCount)
            {
                transportHeader[13] &= ~(TCP_FLAG_FIN | TCP_FLAG_PSH);
            }

            if (index != 0)
            {
                transportHeader[13] &= ~TCP_FLAG_CWR;
            }
        }

        if (performChecksum)
        {
            ChecksumSegment(packet, packetLength, IpHeaderOffset, transportHeaderOffset, isIPv6, !IsUdp);
        }

        MDL * const mdl = IoAllocateMdl(packet, packetLength, FALSE, FALSE, nullptr);

        if (mdl == nullptr)
        {
            ExFreePoolWithTag(packet, SEGLIB_POOL_TAG);
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        MmBuildMdlForNonPagedPool(mdl);

        NET_BUFFER * const netBuffer = NdisAllocateNetBuffer(context->NetBufferPool, mdl, 0, packetLength);

        if (netBuffer == nullptr)
        {
            IoFreeMdl(mdl);
            ExFreePoolWithTag(packet, SEGLIB_POOL_TAG);
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        *tail = netBuffer;
        tail = &NET_BUFFER_NEXT_NB(netBuffer);
    }

    ExFreePoolWithTag(header, SEGLIB_POOL_TAG);

    if (!NT_SUCCESS(status))
    {
        SegLibFreeMultiNbNblClone(clone, 0);
        return status;
    }

    *CloneNetBufferList = clone;
    *OffloadsPerformed = (IsUdp ? SEGLIB_OFFLOAD_PERFORM_USO : SEGLIB_OFFLOAD_PERFORM_LSO) |
        (performChecksum ? SEGLIB_OFFLOAD_PERFORM_CSO : SEGLIB_OFFLOAD_PERFORM_NONE);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
SegLibCreateMultiNbNblClone(
    SEGLIB_CONTEXT * Context,
    NET_BUFFER_LIST * NetBufferList,
    BOOLEAN IsReceive,
    UCHAR IpHeaderOffset,
    SEGLIB_OFFLOAD_OVERRIDE_INFO * OverrideInfo,
    NDIS_HANDLE NetBufferListPool,
    NDIS_HANDLE NetBufferPool,
    USHORT NetBufferListContextSize,
    ULONG DataBackFill,
    NET_BUFFER_LIST ** CloneNetBufferList,
    ULONG * DataOffset,
    ULONG * OffloadsPerformed)
{
    return CreateSegmentedClone(Context, NetBufferList, IsReceive, IpHeaderOffset, OverrideInfo,
        NetBufferListPool, NetBufferPool, NetBufferListContextSize, DataBackFill, FALSE,
        CloneNetBufferList, DataOffset, OffloadsPerformed);
}

_Use_decl_annotations_
NTSTATUS
SegLibCreateMultiNbNblUsoClone(
    SEGLIB_CONTEXT * Context,
    NET_BUFFER_LIST * NetBufferList,
    BOOLEAN IsReceive,
    UCHAR IpHeaderOffset,
    SEGLIB_OFFLOAD_OVERRIDE_INFO * OverrideInfo,
    NDIS_HANDLE NetBufferListPool,
    NDIS_HANDLE NetBufferPool,
    USHORT NetBufferListContextSize,
    ULONG DataBackFill,
    NET_BUFFER_LIST ** CloneNetBufferList,
    ULONG * DataOffset,
    ULONG * OffloadsPerformed)
{
    return CreateSegmentedClone(Context, NetBufferList, IsReceive, IpHeaderOffset, OverrideInfo,
        NetBufferListPool, NetBufferPool, NetBufferListContextSize, DataBackFill, TRUE,
        CloneNetBufferList, DataOffset, OffloadsPerformed);
}
