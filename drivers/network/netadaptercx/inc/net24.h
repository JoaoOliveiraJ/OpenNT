/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     NetAdapterCx 2.4 structure layouts
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

typedef struct _NET_ADAPTER_NDIS_PM_CAPABILITIES_V2_4
{
    ULONG Size;
    ULONG MediaSpecificWakeUpEvents;
    ULONG SupportedProtocolOffloads;
} NET_ADAPTER_NDIS_PM_CAPABILITIES_V2_4;

typedef struct _NET_ADAPTER_RX_CAPABILITIES_V2_4
{
    ULONG Size;
    NET_RX_FRAGMENT_BUFFER_ALLOCATION_MODE AllocationMode;
    NET_RX_FRAGMENT_BUFFER_ATTACHMENT_MODE AttachmentMode;
    UINT32 FragmentRingNumberOfElementsHint;
    SIZE_T MaximumFrameSize;
    SIZE_T MaximumNumberOfQueues;
    union
    {
    struct
    {
    PFN_NET_ADAPTER_RETURN_RX_BUFFER EvtAdapterReturnRxBuffer;
    }
    DUMMYSTRUCTNAME;
    struct
    {
    NET_MEMORY_MAPPING_REQUIREMENT MappingRequirement;
    SIZE_T FragmentBufferAlignment;
    NET_ADAPTER_DMA_CAPABILITIES * DmaCapabilities;
    }
    DUMMYSTRUCTNAME2;
    }
    DUMMYUNIONNAME;
} NET_ADAPTER_RX_CAPABILITIES_V2_4;

typedef struct _NET_ADAPTER_TX_CAPABILITIES_V2_4
{
    ULONG Size;
    NET_MEMORY_MAPPING_REQUIREMENT MappingRequirement;
    SIZE_T PayloadBackfill;
    SIZE_T MaximumNumberOfFragments;
    SIZE_T FragmentBufferAlignment;
    UINT32 FragmentRingNumberOfElementsHint;
    SIZE_T MaximumNumberOfQueues;
    NET_ADAPTER_DMA_CAPABILITIES * DmaCapabilities;
} NET_ADAPTER_TX_CAPABILITIES_V2_4;

typedef struct _NET_PACKET_QUEUE_CONFIG_V2_4
{
    ULONG Size;
    PFN_PACKET_QUEUE_START EvtStart;
    PFN_PACKET_QUEUE_STOP EvtStop;
    PFN_PACKET_QUEUE_ADVANCE EvtAdvance;
    PFN_PACKET_QUEUE_SET_NOTIFICATION_ENABLED EvtSetNotificationEnabled;
    PFN_PACKET_QUEUE_CANCEL EvtCancel;
    NETEXECUTIONCONTEXT ExecutionContext;
} NET_PACKET_QUEUE_CONFIG_V2_4;
