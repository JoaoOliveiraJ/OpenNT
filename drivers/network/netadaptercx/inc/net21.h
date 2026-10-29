/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     NetAdapterCx 2.1 structure layouts
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

typedef struct _NET_ADAPTER_LINK_LAYER_CAPABILITIES_V2_1
{
    ULONG                           Size;
    ULONG64                         MaxTxLinkSpeed;
    ULONG64                         MaxRxLinkSpeed;
} NET_ADAPTER_LINK_LAYER_CAPABILITIES_V2_1;

typedef struct _NET_ADAPTER_NDIS_PM_CAPABILITIES_V2_1
{
    ULONG Size;
    ULONG MediaSpecificWakeUpEvents;
    ULONG SupportedProtocolOffloads;
} NET_ADAPTER_NDIS_PM_CAPABILITIES_V2_1;

typedef struct _NET_ADAPTER_RECEIVE_FILTER_CAPABILITIES_V2_1
{
    ULONG Size;
    NET_PACKET_FILTER_FLAGS SupportedPacketFilters;
    SIZE_T MaximumMulticastAddresses;
    PFN_NET_ADAPTER_SET_RECEIVE_FILTER EvtSetReceiveFilter;
} NET_ADAPTER_RECEIVE_FILTER_CAPABILITIES_V2_1;
