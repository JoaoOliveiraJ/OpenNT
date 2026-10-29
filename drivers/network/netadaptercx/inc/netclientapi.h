/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Dispatch tables between NetAdapterCx and its datapath client
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#include <netclientadapter.h>
#include <netclientdriverconfigurationconstants.h>

typedef ULONG NET_CLIENT_QUERY_DRIVER_CONFIGURATION_ULONG(
    _In_ DRIVER_CONFIG_ENUM ConfigurationEnum);
typedef BOOLEAN NET_CLIENT_QUERY_DRIVER_CONFIGURATION_BOOLEAN(
    _In_ DRIVER_CONFIG_ENUM ConfigurationEnum);

typedef struct _NET_CLIENT_DISPATCH
{
    ULONG Size;
    NET_CLIENT_CREATE_BUFFER_POOL * NetClientCreateBufferPool;
    NET_CLIENT_QUERY_DRIVER_CONFIGURATION_ULONG * NetClientQueryDriverConfigurationUlong;
    NET_CLIENT_QUERY_DRIVER_CONFIGURATION_BOOLEAN * NetClientQueryDriverConfigurationBoolean;
} NET_CLIENT_DISPATCH;

typedef void NET_CLIENT_CONTROL_CALLBACK(
    _In_ void * ClientContext);
typedef BOOLEAN NET_CLIENT_OID_REQUEST_HANDLER(
    _In_ void * ClientContext,
    _In_ NDIS_OID_REQUEST * Request,
    _Out_ NTSTATUS * Status);
typedef NTSTATUS NET_CLIENT_OFFLOAD_INITIALIZE(
    _In_ void * ClientContext);
typedef void NET_CLIENT_WIFI_DESTROY_PEER_ADDRESS_DATAPATH(
    _In_ void * ClientContext,
    _In_ SIZE_T Demux);

typedef struct _NET_CLIENT_CONTROL_DISPATCH
{
    ULONG Size;
    NET_CLIENT_CONTROL_CALLBACK * CreateDatapath;
    NET_CLIENT_CONTROL_CALLBACK * DestroyDatapath;
    NET_CLIENT_CONTROL_CALLBACK * StartDatapath;
    NET_CLIENT_CONTROL_CALLBACK * StopDatapath;
    NET_CLIENT_OID_REQUEST_HANDLER * NdisOidRequestHandler;
    NET_CLIENT_OID_REQUEST_HANDLER * NdisDirectOidRequestHandler;
    NET_CLIENT_OID_REQUEST_HANDLER * NdisSynchronousOidRequestHandler;
    NET_CLIENT_OFFLOAD_INITIALIZE * OffloadInitialize;
    NET_CLIENT_WIFI_DESTROY_PEER_ADDRESS_DATAPATH * WifiDestroyPeerAddressDatapath;
    NET_CLIENT_CONTROL_CALLBACK * PauseOffloadCapabilities;
    NET_CLIENT_CONTROL_CALLBACK * ResumeOffloadCapabilities;
} NET_CLIENT_CONTROL_DISPATCH;
