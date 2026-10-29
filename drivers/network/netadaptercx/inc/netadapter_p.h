/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Private NetAdapterCx interface used by class extensions built on NetAdapterCx
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#include <wdf.h>
#include <netadaptercx.h>
#include <ndiswdf.h>

typedef struct _NETADAPTEREXT_INIT NETADAPTEREXT_INIT;

typedef struct _NET_DRIVER_EXTENSION_CONFIG
{
    ULONG Size;
    BOOLEAN AllowNetAdapterCreation;
} NET_DRIVER_EXTENSION_CONFIG;

typedef struct _NET_ADAPTER_NDIS_PM_CAPABILITIES
{
    ULONG Size;
    ULONG MediaSpecificWakeUpEvents;
    ULONG SupportedProtocolOffloads;
} NET_ADAPTER_NDIS_PM_CAPABILITIES;

typedef
_Function_class_(EVT_NET_ADAPTER_UPDATE_NDIS_PM_PARAMETERS)
_IRQL_requires_same_
_IRQL_requires_max_(PASSIVE_LEVEL)
void
NTAPI
EVT_NET_ADAPTER_UPDATE_NDIS_PM_PARAMETERS(
    _In_ NETADAPTER Adapter,
    _Inout_ NDIS_PM_PARAMETERS * PmParameters);

typedef EVT_NET_ADAPTER_UPDATE_NDIS_PM_PARAMETERS * PFN_NET_ADAPTER_UPDATE_NDIS_PM_PARAMETERS;

typedef struct _NET_ADAPTER_EXTENSION_POWER_POLICY_CALLBACKS
{
    ULONG Size;
    PFN_NET_ADAPTER_UPDATE_NDIS_PM_PARAMETERS EvtUpdateNdisPmParameters;
} NET_ADAPTER_EXTENSION_POWER_POLICY_CALLBACKS;

typedef
_Function_class_(EVT_NET_ADAPTER_PRE_PROCESS_OID_REQUEST)
_IRQL_requires_same_
_IRQL_requires_max_(DISPATCH_LEVEL)
void
NTAPI
EVT_NET_ADAPTER_PRE_PROCESS_OID_REQUEST(
    _In_ NETADAPTER Adapter,
    _In_ NDIS_OID_REQUEST * Request,
    _In_ WDFCONTEXT DispatchContext);

typedef EVT_NET_ADAPTER_PRE_PROCESS_OID_REQUEST * PFN_NET_ADAPTER_PRE_PROCESS_OID_REQUEST;

typedef
_Function_class_(EVT_NET_ADAPTER_PRE_PROCESS_DIRECT_OID_REQUEST)
_IRQL_requires_same_
_IRQL_requires_max_(DISPATCH_LEVEL)
void
NTAPI
EVT_NET_ADAPTER_PRE_PROCESS_DIRECT_OID_REQUEST(
    _In_ NETADAPTER Adapter,
    _In_ NDIS_OID_REQUEST * Request,
    _In_ WDFCONTEXT DispatchContext);

typedef EVT_NET_ADAPTER_PRE_PROCESS_DIRECT_OID_REQUEST * PFN_NET_ADAPTER_PRE_PROCESS_DIRECT_OID_REQUEST;

typedef
_Function_class_(EVT_NETEX_ADAPTER_PREPROCESS_DIRECT_OID)
_IRQL_requires_same_
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
NTAPI
EVT_NETEX_ADAPTER_PREPROCESS_DIRECT_OID(
    _In_ NETADAPTER Adapter,
    _In_ NDIS_OID_REQUEST * Request,
    _In_ WDFCONTEXT DispatchContext);

typedef EVT_NETEX_ADAPTER_PREPROCESS_DIRECT_OID * PFN_NETEX_ADAPTER_PREPROCESS_DIRECT_OID;

typedef
_Function_class_(EVT_NET_ADAPTER_TX_PEER_DEMUX)
_IRQL_requires_same_
_IRQL_requires_max_(DISPATCH_LEVEL)
SIZE_T
NTAPI
EVT_NET_ADAPTER_TX_PEER_DEMUX(
    _In_ NETADAPTER Adapter,
    _In_ NET_EUI48_ADDRESS const * Address);

typedef EVT_NET_ADAPTER_TX_PEER_DEMUX * PFN_NET_ADAPTER_TX_PEER_DEMUX;

typedef
_Function_class_(EVT_NET_DEVICE_RESET)
_IRQL_requires_same_
_IRQL_requires_max_(PASSIVE_LEVEL)
void
NTAPI
EVT_NET_DEVICE_RESET(
    _In_ WDFDEVICE Device);

typedef EVT_NET_DEVICE_RESET * PFN_NET_DEVICE_RESET;

typedef struct _NET_DEVICE_RESET_CONFIG
{
    ULONG Size;
    PFN_NET_DEVICE_RESET EvtDeviceReset;
} NET_DEVICE_RESET_CONFIG;

typedef
_Function_class_(EVT_NET_BUFFER_QUEUE_CALLBACK)
_IRQL_requires_same_
_IRQL_requires_max_(DISPATCH_LEVEL)
void
NTAPI
EVT_NET_BUFFER_QUEUE_CALLBACK(
    _In_ NETBUFFERQUEUE BufferQueue);

typedef EVT_NET_BUFFER_QUEUE_CALLBACK * PFN_NET_BUFFER_QUEUE_CALLBACK;

typedef struct _NET_BUFFER_QUEUE_CONFIG
{
    ULONG Size;
    SIZE_T BufferSize;
    SIZE_T BufferAlignment;
    PFN_NET_BUFFER_QUEUE_CALLBACK EvtPostAndDrain;
    PFN_NET_BUFFER_QUEUE_CALLBACK EvtReturnBuffers;
    PFN_NET_BUFFER_QUEUE_CALLBACK EvtCancel;
    NET_ADAPTER_DMA_CAPABILITIES * DmaCapabilities;
} NET_BUFFER_QUEUE_CONFIG;

/* FIXME: values unverified, the 22621 symbols have no NET_WAKE_REASON_TYPE */
typedef enum _NET_WAKE_REASON_TYPE
{
    NetWakeReasonTypeNone = 0,
    NetWakeReasonTypeBitmapPattern,
    NetWakeReasonTypeMagicPacket,
    NetWakeReasonTypeMediaChange,
    NetWakeReasonTypePacketFilterMatch,
    NetWakeReasonTypeEapolPacket,
    NetWakeReasonTypeDevice,
    NetWakeReasonTypeNdis,
} NET_WAKE_REASON_TYPE;

typedef struct _NDIS_MINIPORT_BLOCK_TYPE
{
    UCHAR Reserved;
} NDIS_MINIPORT_BLOCK_TYPE;

WDF_DECLARE_CONTEXT_TYPE(NDIS_MINIPORT_BLOCK_TYPE);

#define NETCX_GSO_SOFTWARE_FALLBACK_MAX_SIZE 0x10000
#define NETCX_GSO_SOFTWARE_FALLBACK_MIN_SEGMENT_COUNT 2
