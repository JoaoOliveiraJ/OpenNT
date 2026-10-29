/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     NetAdapterCx 2.0 structure layouts
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

typedef struct _NET_ADAPTER_LINK_LAYER_CAPABILITIES_V2_0
{
    ULONG                           Size;
    ULONG64                         MaxTxLinkSpeed;
    ULONG64                         MaxRxLinkSpeed;
} NET_ADAPTER_LINK_LAYER_CAPABILITIES_V2_0;

typedef struct _NET_ADAPTER_NDIS_PM_CAPABILITIES_V2_0
{
    ULONG Size;
    ULONG MediaSpecificWakeUpEvents;
} NET_ADAPTER_NDIS_PM_CAPABILITIES_V2_0;

typedef struct _NET_PACKET_QUEUE_CONFIG_V2_0
{
    ULONG Size;
    PFN_PACKET_QUEUE_START EvtStart;
    PFN_PACKET_QUEUE_STOP EvtStop;
    PFN_PACKET_QUEUE_ADVANCE EvtAdvance;
    PFN_PACKET_QUEUE_SET_NOTIFICATION_ENABLED EvtSetNotificationEnabled;
    PFN_PACKET_QUEUE_CANCEL EvtCancel;
} NET_PACKET_QUEUE_CONFIG_V2_0;
