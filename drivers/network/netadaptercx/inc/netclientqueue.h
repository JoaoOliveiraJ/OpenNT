/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Packet queue interface between NetAdapterCx and its datapath client
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#include <netclienttypes.h>
#include <net/ringcollection.h>
#include <net/extension.h>

typedef struct _NET_CLIENT_QUEUE_CONFIG
{
    ULONG Size;
    UINT32 NumberOfPackets;
    UINT32 NumberOfFragments;
    NET_CLIENT_EXTENSION * Extensions;
    SIZE_T NumberOfExtensions;
    NET_CLIENT_QUEUE_TX_DEMUX_PROPERTY DemuxPeerAddressProperty;
    NET_CLIENT_QUEUE_TX_DEMUX_PROPERTY DemuxWmmProperty;
    NET_CLIENT_QUEUE_TX_DEMUX_PROPERTY Demux8021pProperty;
} NET_CLIENT_QUEUE_CONFIG;

inline
void
NET_CLIENT_QUEUE_CONFIG_INIT(
    _Out_ NET_CLIENT_QUEUE_CONFIG * QueueConfig,
    _In_ UINT32 NumberOfPackets,
    _In_ UINT32 NumberOfFragments)
{
    RtlZeroMemory(QueueConfig, sizeof(*QueueConfig));
    QueueConfig->Size = sizeof(*QueueConfig);
    QueueConfig->NumberOfPackets = NumberOfPackets;
    QueueConfig->NumberOfFragments = NumberOfFragments;
}

typedef
void
NET_CLIENT_QUEUE_NOTIFY(
    _In_ void * QueueContext);

typedef
NET_CLIENT_QUEUE_TX_DEMUX_PROPERTY const *
NET_CLIENT_QUEUE_GET_TX_DEMUX_PROPERTY(
    _In_ NET_CLIENT_QUEUE Queue,
    _In_ NET_CLIENT_QUEUE_TX_DEMUX_TYPE Type);

typedef struct _NET_CLIENT_QUEUE_NOTIFY_DISPATCH
{
    ULONG Size;
    NET_CLIENT_QUEUE_NOTIFY * Notify;
    NET_CLIENT_QUEUE_GET_TX_DEMUX_PROPERTY * GetTxDemuxProperty;
} NET_CLIENT_QUEUE_NOTIFY_DISPATCH;

typedef
void
NET_CLIENT_QUEUE_START(
    _In_ NET_CLIENT_QUEUE Queue);

typedef
void
NET_CLIENT_QUEUE_STOP(
    _In_ NET_CLIENT_QUEUE Queue);

typedef
void
NET_CLIENT_QUEUE_ADVANCE(
    _In_ NET_CLIENT_QUEUE Queue);

typedef
void
NET_CLIENT_QUEUE_CANCEL(
    _In_ NET_CLIENT_QUEUE Queue);

typedef
void
NET_CLIENT_QUEUE_SET_ARMED(
    _In_ NET_CLIENT_QUEUE Queue,
    _In_ BOOLEAN IsArmed);

typedef
void
NET_CLIENT_QUEUE_GET_EXTENSION(
    _In_ NET_CLIENT_QUEUE Queue,
    _In_ NET_CLIENT_EXTENSION const * ExtensionToQuery,
    _Out_ NET_EXTENSION * Extension);

typedef
NET_RING_COLLECTION const *
NET_CLIENT_QUEUE_GET_RING_COLLECTION(
    _In_ NET_CLIENT_QUEUE Queue);

typedef struct _NET_CLIENT_QUEUE_DISPATCH
{
    ULONG Size;
    NET_CLIENT_QUEUE_START * Start;
    NET_CLIENT_QUEUE_STOP * Stop;
    NET_CLIENT_QUEUE_ADVANCE * Advance;
    NET_CLIENT_QUEUE_CANCEL * Cancel;
    NET_CLIENT_QUEUE_SET_ARMED * SetArmed;
    NET_CLIENT_QUEUE_GET_EXTENSION * GetExtension;
    NET_CLIENT_QUEUE_GET_RING_COLLECTION * GetNetDatapathDescriptor;
} NET_CLIENT_QUEUE_DISPATCH;
