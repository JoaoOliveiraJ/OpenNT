/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Packet Monitor client interface used by NetAdapterCx
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#include <netiodef.h>
#include <pktmonloc.h>

/* TODO: attach to a Packet Monitor NMR provider once OpenNT has one. */

DECLARE_HANDLE(PKTMON_COMPONENT_HANDLE);
DECLARE_HANDLE(PKTMON_LOWEREDGE_HANDLE);

#define PKTMON_EDGE_LOWER L"Lower"

typedef enum _PKTMON_COMPONENT_TYPE
{
    PktMonComp_Ndis = 1,
    PktMonComp_Miniport = 2,
    PktMonComp_Filter = 3,
    PktMonComp_Protocol = 4,
    PktMonComp_VmsVmNic = 5,
    PktMonComp_VmsMiniport = 6,
    PktMonComp_VmsExtMiniport = 7,
    PktMonComp_VmsProtocolNic = 8,
    PktMonComp_NetVsc = 9,
    PktMonComp_HTTP = 10,
    PktMonComp_IpInterface = 11,
    PktMonComp_Slbmux = 12,
    PktMonComp_Ipsec = 13,
    PktMonComp_NetCx = 14,
    PktMonComp_HTTPMessage = 15,
} PKTMON_COMPONENT_TYPE;

typedef enum _PKTMON_DIRECTION
{
    PktMonDir_In = 1,
    PktMonDir_Out = 2,
} PKTMON_DIRECTION;

typedef enum _PKTMON_DIRECTION_TAG
{
    PktMonDirTag_Unspecified = 0,
    PktMonDirTag_In = 1,
    PktMonDirTag_Out = 2,
    PktMonDirTag_Rx = 3,
    PktMonDirTag_Tx = 4,
    PktMonDirTag_Ingress = 5,
    PktMonDirTag_Egress = 6,
} PKTMON_DIRECTION_TAG;

typedef enum _PKTMON_PACKET_TYPE
{
    PktMonPayload_Unknown = 0,
    PktMonPayload_Ethernet = 1,
    PktMonPayload_WiFi = 2,
    PktMonPayload_IP = 3,
    PktMonPayload_HTTP = 4,
    PktMonPayload_TCP = 5,
    PktMonPayload_UDP = 6,
    PktMonPayload_ARP = 7,
    PktMonPayload_ICMP = 8,
    PktMonPayload_ESP = 9,
    PktMonPayload_AH = 10,
    PktMonPayload_L4Payload = 11,
} PKTMON_PACKET_TYPE;

typedef enum _PKTMON_COMP_PROPERTY_ID
{
    PktMonCompProp_IfIndex = 1,
    PktMonCompProp_MiniportIfIndex = 2,
    PktMonCompProp_LowerIfIndex = 3,
    PktMonCompProp_IfGuid = 4,
    PktMonCompProp_NdisMedium = 5,
    PktMonCompProp_PhysAddress = 6,
    PktMonCompProp_EtherType = 7,
    PktMonCompProp_OptDataPath = 8,
    PktMonCompProp_NdisObject = 9,
    PktMonCompProp_VMSwitchName = 10,
    PktMonCompProp_VmsExtIfIndex = 11,
    PktMonCompProp_LowestIfIndex = 12,
    PktMonCompProp_IpAddress = 13,
    PktMonCompProp_IpIfIndex = 14,
    PktMonCompProp_Vsid = 15,
    PktMonCompProp_Vlan = 16,
    PktMonCompProp_CompartmentId = 17,
    PktMonCompProp_Max = 18,
} PKTMON_COMP_PROPERTY_ID;

typedef enum _PKTMON_DROP_REASON
{
    PktMonDrop_Unknown = 0,
    PktMonDrop_NetCx_NetPacketLayoutParseFailure = 1501,
    PktMonDrop_NetCx_SoftwareChecksumFailure = 1502,
    PktMonDrop_NetCx_NicQueueStop = 1503,
    PktMonDrop_NetCx_InvalidNetBufferLength = 1504,
    PktMonDrop_NetCx_LSOFailure = 1505,
    PktMonDrop_NetCx_USOFailure = 1506,
    PktMonDrop_NetCx_BufferBounceFailureAndPacketIgnore = 1507,
} PKTMON_DROP_REASON;

typedef struct _PKTMON_COMPONENT_CONTEXT
{
    LIST_ENTRY ListLink;
    LIST_ENTRY EdgeList;
    LONG EdgeCount;
    void * CompHandle;
    PKTMON_COMPONENT_TYPE CompType;
    PKTMON_PACKET_TYPE PacketType;
    int FlowEnabled : 1;
    int DropEnabled : 1;
} PKTMON_COMPONENT_CONTEXT;

typedef struct _PKTMON_EDGE_CONTEXT
{
    LIST_ENTRY ListLink;
    void * EdgeHandle;
    PKTMON_COMPONENT_CONTEXT * CompContext;
    PKTMON_PACKET_TYPE PacketType;
} PKTMON_EDGE_CONTEXT;

typedef void PKTMON_CLIENT_ENUMERATE_COMPONENTS(void);

FORCEINLINE
NTSTATUS
PktMonClientInitializeNoSync(
    _In_ NPI_MODULEID const * ModuleId,
    _In_ PKTMON_CLIENT_ENUMERATE_COMPONENTS * EnumComponents,
    _In_ PKTMON_CLIENT_ENUMERATE_COMPONENTS * CleanupComponents)
{
    UNREFERENCED_PARAMETER(ModuleId);
    UNREFERENCED_PARAMETER(EnumComponents);
    UNREFERENCED_PARAMETER(CleanupComponents);
    return STATUS_SUCCESS;
}

FORCEINLINE
void
PktMonClientUninitialize(void)
{
}

FORCEINLINE
NTSTATUS
PktMonClientComponentRegister(
    _Out_ PKTMON_COMPONENT_CONTEXT * CompContext,
    _In_ UNICODE_STRING const * Name,
    _In_ UNICODE_STRING const * Description,
    _In_ PKTMON_COMPONENT_TYPE Type,
    _In_ NDIS_MEDIUM MediaType,
    _In_ PKTMON_DIRECTION_TAG DirTagIn,
    _In_ PKTMON_DIRECTION_TAG DirTagOut)
{
    UNREFERENCED_PARAMETER(Name);
    UNREFERENCED_PARAMETER(Description);
    UNREFERENCED_PARAMETER(MediaType);
    UNREFERENCED_PARAMETER(DirTagIn);
    UNREFERENCED_PARAMETER(DirTagOut);
    RtlZeroMemory(CompContext, sizeof(*CompContext));
    InitializeListHead(&CompContext->ListLink);
    InitializeListHead(&CompContext->EdgeList);
    CompContext->CompType = Type;
    return STATUS_NOT_FOUND;
}

FORCEINLINE
void
PktMonClientComponentUnregister(
    _Inout_ PKTMON_COMPONENT_CONTEXT * CompContext)
{
    UNREFERENCED_PARAMETER(CompContext);
}

FORCEINLINE
NTSTATUS
PktMonClientSetCompProperty(
    _In_ PKTMON_COMPONENT_CONTEXT * CompContext,
    _In_ PKTMON_COMP_PROPERTY_ID PropertyId,
    _In_reads_bytes_(PropertySize) void const * Property,
    _In_ ULONG PropertySize)
{
    UNREFERENCED_PARAMETER(CompContext);
    UNREFERENCED_PARAMETER(PropertyId);
    UNREFERENCED_PARAMETER(Property);
    UNREFERENCED_PARAMETER(PropertySize);
    return STATUS_NOT_FOUND;
}

FORCEINLINE
NTSTATUS
PktMonClientAddEdge(
    _In_ PKTMON_COMPONENT_CONTEXT * CompContext,
    _In_ UNICODE_STRING * Name,
    _In_ PKTMON_DIRECTION_TAG DirTagIn,
    _In_ PKTMON_DIRECTION_TAG DirTagOut,
    _In_ NDIS_MEDIUM MediaType,
    _Out_ PKTMON_EDGE_CONTEXT * EdgeContext)
{
    UNREFERENCED_PARAMETER(Name);
    UNREFERENCED_PARAMETER(DirTagIn);
    UNREFERENCED_PARAMETER(DirTagOut);
    UNREFERENCED_PARAMETER(MediaType);
    RtlZeroMemory(EdgeContext, sizeof(*EdgeContext));
    InitializeListHead(&EdgeContext->ListLink);
    EdgeContext->CompContext = CompContext;
    return STATUS_NOT_FOUND;
}

#define PKTMON_DROP_NBL(_CompContext, _Nbl, _Direction, _Reason, _Location) \
    { (void)(_CompContext); (void)(_Nbl); (void)(_Direction); (void)(_Reason); (void)(_Location); }

#define PKTMON_LOG_NBL_NDIS(_EdgeContext, _Nbl, _Direction) \
    { (void)(_EdgeContext); (void)(_Nbl); (void)(_Direction); }
