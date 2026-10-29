/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     NetAdapterCx client function and structure tables
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

extern "C"
{

NETADAPTER_INIT * NETEXPORT(NetAdapterInitAllocate)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ WDFDEVICE Device);
void NETEXPORT(NetAdapterInitFree)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER_INIT * AdapterInit);
void NETEXPORT(NetAdapterInitSetDatapathCallbacks)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _Inout_ NETADAPTER_INIT * AdapterInit, _In_ NET_ADAPTER_DATAPATH_CALLBACKS * DatapathCallbacks);
NTSTATUS NETEXPORT(NetAdapterCreate)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER_INIT * AdapterInit, _In_opt_ WDF_OBJECT_ATTRIBUTES * AdapterAttributes, _Out_ NETADAPTER * Adapter);
NTSTATUS NETEXPORT(NetAdapterStart)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter);
void NETEXPORT(NetAdapterStop)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter);
void NETEXPORT(NetAdapterSetLinkLayerCapabilities)(_In_ NET_DRIVER_GLOBALS *                   DriverGlobals, _In_ NETADAPTER                             Adapter, _In_ NET_ADAPTER_LINK_LAYER_CAPABILITIES *  LinkLayerCapabilities);
void NETEXPORT(NetAdapterSetLinkLayerMtuSize)(_In_ NET_DRIVER_GLOBALS *                   DriverGlobals, _In_ NETADAPTER                             Adapter, _In_ ULONG                                  MtuSize);
void NETEXPORT(NetAdapterPowerOffloadSetArpCapabilities)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ NETADAPTER Adapter, _In_ const NET_ADAPTER_POWER_OFFLOAD_ARP_CAPABILITIES * Capabilities);
void NETEXPORT(NetAdapterPowerOffloadSetNSCapabilities)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ NETADAPTER Adapter, _In_ const NET_ADAPTER_POWER_OFFLOAD_NS_CAPABILITIES * Capabilities);
void NETEXPORT(NetAdapterWakeSetBitmapCapabilities)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ NETADAPTER Adapter, _In_ const NET_ADAPTER_WAKE_BITMAP_CAPABILITIES * Capabilities);
void NETEXPORT(NetAdapterWakeSetMediaChangeCapabilities)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ NETADAPTER Adapter, _In_ const NET_ADAPTER_WAKE_MEDIA_CHANGE_CAPABILITIES * Capabilities);
void NETEXPORT(NetAdapterWakeSetMagicPacketCapabilities)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ NETADAPTER Adapter, _In_ const NET_ADAPTER_WAKE_MAGIC_PACKET_CAPABILITIES * Capabilities);
void NETEXPORT(NetAdapterWakeSetPacketFilterCapabilities)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ NETADAPTER Adapter, _In_ const NET_ADAPTER_WAKE_PACKET_FILTER_CAPABILITIES * Capabilities);
void NETEXPORT(NetAdapterSetDataPathCapabilities)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ NET_ADAPTER_TX_CAPABILITIES * TxCapabilities, _In_ NET_ADAPTER_RX_CAPABILITIES * RxCapabilities);
void NETEXPORT(NetAdapterSetLinkState)(_In_ NET_DRIVER_GLOBALS *    DriverGlobals, _In_ NETADAPTER              Adapter, _In_ NET_ADAPTER_LINK_STATE * State);
NET_LUID NETEXPORT(NetAdapterGetNetLuid)(_In_     NET_DRIVER_GLOBALS *                Globals, _In_     NETADAPTER                          Adapter);
NTSTATUS NETEXPORT(NetAdapterOpenConfiguration)(_In_     NET_DRIVER_GLOBALS *                Globals, _In_     NETADAPTER                          Adapter, _In_opt_ WDF_OBJECT_ATTRIBUTES *             ConfigurationAttributes, _Out_    NETCONFIGURATION *                  Configuration);
void NETEXPORT(NetAdapterSetPermanentLinkLayerAddress)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ NET_ADAPTER_LINK_LAYER_ADDRESS * LinkLayerAddress);
void NETEXPORT(NetAdapterSetCurrentLinkLayerAddress)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ NET_ADAPTER_LINK_LAYER_ADDRESS * LinkLayerAddress);
void NETEXPORT(NetAdapterOffloadSetChecksumCapabilities)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ NET_ADAPTER_OFFLOAD_CHECKSUM_CAPABILITIES * HardwareCapabilities);
BOOLEAN NETEXPORT(NetOffloadIsChecksumIPv4Enabled)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETOFFLOAD Offload);
BOOLEAN NETEXPORT(NetOffloadIsChecksumTcpEnabled)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETOFFLOAD Offload);
BOOLEAN NETEXPORT(NetOffloadIsChecksumUdpEnabled)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETOFFLOAD Offload);
void NETEXPORT(NetAdapterReportWakeReasonPacket)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ const NET_ADAPTER_WAKE_REASON_PACKET * Reason);
void NETEXPORT(NetAdapterReportWakeReasonMediaChange)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ NET_IF_MEDIA_CONNECT_STATE Reason);
NETADAPTER NETEXPORT(NetAdapterInitGetCreatedAdapter)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER_INIT * AdapterInit);
NETADAPTEREXT_INIT * NETEXPORT(NetAdapterExtensionInitAllocate)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER_INIT * AdapterInit);
void NETEXPORT(NetAdapterExtensionInitSetOidRequestPreprocessCallback)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _Inout_ NETADAPTEREXT_INIT * AdapterExtensionInit, _In_ PFN_NET_ADAPTER_PRE_PROCESS_OID_REQUEST PreprocessOidRequest);
void NETEXPORT(NetAdapterDispatchPreprocessedOidRequest)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ NDIS_OID_REQUEST * Request, _In_ WDFCONTEXT Context);
WDFOBJECT NETEXPORT(NetAdapterGetParent)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter);
ULONG NETEXPORT(NetAdapterGetLinkLayerMtuSize)(_In_ NET_DRIVER_GLOBALS *                   DriverGlobals, _In_ NETADAPTER                             Adapter);
void NETEXPORT(NetAdapterExtensionInitSetNdisPmCapabilities)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _Inout_ NETADAPTEREXT_INIT* AdapterExtensionInit, _In_ CONST NET_ADAPTER_NDIS_PM_CAPABILITIES* Capabilities);
NDIS_HANDLE NETEXPORT(NetAdapterWdmGetNdisHandle)(_In_ NET_DRIVER_GLOBALS *              Globals, _In_ NETADAPTER                        Adapter);
NDIS_HANDLE NETEXPORT(NetAdapterDriverWdmGetHandle)(_In_     NET_DRIVER_GLOBALS *        Globals, _In_     WDFDRIVER                   Driver);
void NETEXPORT(NetConfigurationClose)(_In_ NET_DRIVER_GLOBALS *              Globals, _In_ NETCONFIGURATION                  Configuration);
NTSTATUS NETEXPORT(NetConfigurationOpenSubConfiguration)(_In_     NET_DRIVER_GLOBALS *       Globals, _In_     NETCONFIGURATION           Configuration, _In_     PCUNICODE_STRING           SubConfigurationName, _In_opt_ WDF_OBJECT_ATTRIBUTES *    SubConfigurationAttributes, _Out_    NETCONFIGURATION*          SubConfiguration);
NTSTATUS NETEXPORT(NetConfigurationQueryUlong)(_In_  NET_DRIVER_GLOBALS *                  Globals, _In_  NETCONFIGURATION                      Configuration, _In_  NET_CONFIGURATION_QUERY_ULONG_FLAGS   Flags, _In_  PCUNICODE_STRING                      ValueName, _Out_ PULONG                                Value);
NTSTATUS NETEXPORT(NetConfigurationQueryString)(_In_     NET_DRIVER_GLOBALS *                  Globals, _In_     NETCONFIGURATION                      Configuration, _In_     PCUNICODE_STRING                      ValueName, _In_opt_ WDF_OBJECT_ATTRIBUTES *               StringAttributes, _Out_    WDFSTRING*                            WdfString);
NTSTATUS NETEXPORT(NetConfigurationQueryMultiString)(_In_     NET_DRIVER_GLOBALS *                  Globals, _In_     NETCONFIGURATION                      Configuration, _In_     PCUNICODE_STRING                      ValueName, _In_opt_ WDF_OBJECT_ATTRIBUTES *               StringsAttributes, _Inout_  WDFCOLLECTION                         Collection);
NTSTATUS NETEXPORT(NetConfigurationQueryBinary)(_In_     NET_DRIVER_GLOBALS *                  Globals, _In_     NETCONFIGURATION                      Configuration, _In_     PCUNICODE_STRING                      ValueName, _Strict_type_match_ _In_ POOL_TYPE                             PoolType, _In_opt_ WDF_OBJECT_ATTRIBUTES *               MemoryAttributes, _Out_    WDFMEMORY*                            WdfMemory);
NTSTATUS NETEXPORT(NetConfigurationQueryLinkLayerAddress)(_In_  NET_DRIVER_GLOBALS * DriverGlobals, _In_  NETCONFIGURATION Configuration, _Out_ NET_ADAPTER_LINK_LAYER_ADDRESS * LinkLayerAddress);
NTSTATUS NETEXPORT(NetConfigurationAssignUlong)(_In_  NET_DRIVER_GLOBALS *                  Globals, _In_  NETCONFIGURATION                      Configuration, _In_  PCUNICODE_STRING                      ValueName, _In_  ULONG                                 Value);
NTSTATUS NETEXPORT(NetConfigurationAssignUnicodeString)(_In_  NET_DRIVER_GLOBALS *                  Globals, _In_  NETCONFIGURATION                      Configuration, _In_  PCUNICODE_STRING                      ValueName, _In_  PCUNICODE_STRING                      Value);
NTSTATUS NETEXPORT(NetConfigurationAssignMultiString)(_In_  NET_DRIVER_GLOBALS *                  Globals, _In_  NETCONFIGURATION                      Configuration, _In_  PCUNICODE_STRING                      ValueName, _In_  WDFCOLLECTION                         StringsCollection);
NTSTATUS NETEXPORT(NetConfigurationAssignBinary)(_In_                               NET_DRIVER_GLOBALS *      Globals, _In_                               NETCONFIGURATION          Configuration, _In_                               PCUNICODE_STRING          ValueName, _In_reads_bytes_(BufferLength)     void *                     Buffer, _In_                               ULONG                     BufferLength);
NTSTATUS NETEXPORT(NetDeviceInitConfig)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _Inout_ WDFDEVICE_INIT * DeviceInit);
NTSTATUS NETEXPORT(NetDeviceOpenConfiguration)(_In_ NET_DRIVER_GLOBALS * Globals, _In_ WDFDEVICE Device, _In_opt_ WDF_OBJECT_ATTRIBUTES * ConfigurationAttributes, _Out_ NETCONFIGURATION * Configuration);
void NETEXPORT(NetDeviceInitSetPowerPolicyEventCallbacks)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _Inout_ PWDFDEVICE_INIT DeviceInit, _In_ CONST NET_DEVICE_POWER_POLICY_EVENT_CALLBACKS * Callbacks);
void NETEXPORT(NetDeviceInitSetResetConfig)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ PWDFDEVICE_INIT DeviceInit, _In_ NET_DEVICE_RESET_CONFIG * ResetConfig);
NTSTATUS NETEXPORT(NetDeviceAssignSupportedOidList)(_In_ NET_DRIVER_GLOBALS * Globals, _In_ WDFDEVICE Device, _In_reads_(SupportedOidsCount) NDIS_OID const * SupportedOids, _In_ SIZE_T SupportedOidsCount);
NET_POWER_OFFLOAD_TYPE NETEXPORT(NetPowerOffloadGetType)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ NETPOWEROFFLOAD PowerOffload);
void NETEXPORT(NetPowerOffloadGetArpParameters)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ NETPOWEROFFLOAD PowerOffload, _Inout_ NET_POWER_OFFLOAD_ARP_PARAMETERS * Parameters);
void NETEXPORT(NetPowerOffloadGetNSParameters)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ NETPOWEROFFLOAD PowerOffload, _Inout_ NET_POWER_OFFLOAD_NS_PARAMETERS * Parameters);
void NETEXPORT(NetDeviceGetPowerOffloadList)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ WDFDEVICE Device, _Inout_ NET_POWER_OFFLOAD_LIST * List);
SIZE_T NETEXPORT(NetPowerOffloadListGetCount)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ const NET_POWER_OFFLOAD_LIST * List);
NETPOWEROFFLOAD NETEXPORT(NetPowerOffloadListGetElement)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ const NET_POWER_OFFLOAD_LIST * List, _In_ SIZE_T Index);
void NETEXPORT(NetAdapterSetReceiveScalingCapabilities)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ NET_ADAPTER_RECEIVE_SCALING_CAPABILITIES const * Capabilities);
NTSTATUS NETEXPORT(NetRxQueueCreate)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _Inout_ NETRXQUEUE_INIT * NetRxQueueInit, _In_opt_ WDF_OBJECT_ATTRIBUTES * RxQueueAttributes, _In_ NET_PACKET_QUEUE_CONFIG * Configuration, _Out_ NETPACKETQUEUE * RxQueue);
void NETEXPORT(NetRxQueueNotifyMoreReceivedPacketsAvailable)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETPACKETQUEUE RxQueue);
ULONG NETEXPORT(NetRxQueueInitGetQueueId)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETRXQUEUE_INIT * NetRxQueueInit);
NET_RING_COLLECTION const * NETEXPORT(NetRxQueueGetRingCollection)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETPACKETQUEUE NetRxQueue);
void NETEXPORT(NetRxQueueGetExtension)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETPACKETQUEUE NetRxQueue, _In_ NET_EXTENSION_QUERY const * Query, _Out_ NET_EXTENSION* Extension);
NTSTATUS NETEXPORT(NetTxQueueCreate)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _Inout_ NETTXQUEUE_INIT * NetTxQueueInit, _In_opt_ WDF_OBJECT_ATTRIBUTES * TxQueueAttributes, _In_ NET_PACKET_QUEUE_CONFIG * Configuration, _Out_ NETPACKETQUEUE* TxQueue);
void NETEXPORT(NetTxQueueNotifyMoreCompletedPacketsAvailable)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETPACKETQUEUE TxQueue);
ULONG NETEXPORT(NetTxQueueInitGetQueueId)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETTXQUEUE_INIT * NetTxQueueInit);
NET_RING_COLLECTION const * NETEXPORT(NetTxQueueGetRingCollection)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETPACKETQUEUE NetTxQueue);
void NETEXPORT(NetTxQueueGetExtension)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETPACKETQUEUE NetTxQueue, _In_ NET_EXTENSION_QUERY const * Query, _Out_ NET_EXTENSION* Extension);
NET_WAKE_SOURCE_TYPE NETEXPORT(NetWakeSourceGetType)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ NETWAKESOURCE WakeSource);
NETADAPTER NETEXPORT(NetWakeSourceGetAdapter)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ NETWAKESOURCE WakeSource);
void NETEXPORT(NetWakeSourceGetBitmapParameters)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ NETWAKESOURCE WakeSource, _Inout_ NET_WAKE_SOURCE_BITMAP_PARAMETERS * Parameters);
void NETEXPORT(NetWakeSourceGetMediaChangeParameters)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETWAKESOURCE WakeSource, _Inout_ NET_WAKE_SOURCE_MEDIA_CHANGE_PARAMETERS * Parameters);
void NETEXPORT(NetDeviceGetWakeSourceList)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ WDFDEVICE Device, _Inout_ NET_WAKE_SOURCE_LIST * List);
SIZE_T NETEXPORT(NetWakeSourceListGetCount)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ const NET_WAKE_SOURCE_LIST * List);
NETWAKESOURCE NETEXPORT(NetWakeSourceListGetElement)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ const NET_WAKE_SOURCE_LIST * List, _In_ SIZE_T Index);
void NETEXPORT(NetAdapterWakeSetEapolPacketCapabilities)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ NETADAPTER Adapter, _In_ const NET_ADAPTER_WAKE_EAPOL_PACKET_CAPABILITIES * Capabilities);
VOID NETEXPORT(NetAdapterSetReceiveFilterCapabilities)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ const NET_ADAPTER_RECEIVE_FILTER_CAPABILITIES * ReceiveFilter);
NET_PACKET_FILTER_FLAGS NETEXPORT(NetReceiveFilterGetPacketFilter)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETRECEIVEFILTER ReceiveFilter);
SIZE_T NETEXPORT(NetReceiveFilterGetMulticastAddressCount)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETRECEIVEFILTER ReceiveFilter);
NET_ADAPTER_LINK_LAYER_ADDRESS const * NETEXPORT(NetReceiveFilterGetMulticastAddressList)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETRECEIVEFILTER ReceiveFilter);
NTSTATUS NETEXPORT(NetDriverExtensionInitialize)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ WDFDRIVER Driver, _In_ const NET_DRIVER_EXTENSION_CONFIG * Config);
void NETEXPORT(NetAdapterExtensionInitSetDirectOidRequestPreprocessCallback)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _Inout_ NETADAPTEREXT_INIT * AdapterExtensionInit, _In_ PFN_NET_ADAPTER_PRE_PROCESS_DIRECT_OID_REQUEST PreprocessDirectOidRequest);
void NETEXPORT(NetExAdapterInitSetDirectOidPreprocessCallback)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _Inout_ NETADAPTEREXT_INIT * AdapterExtensionInit, _In_ PFN_NETEX_ADAPTER_PREPROCESS_DIRECT_OID PreprocessDirectOid);
void NETEXPORT(NetAdapterExtensionInitSetTxPeerDemuxCallback)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _Inout_ NETADAPTEREXT_INIT * AdapterExtensionInit, _In_ PFN_NET_ADAPTER_TX_PEER_DEMUX TxPeerDemux);
void NETEXPORT(NetAdapterDispatchPreprocessedDirectOidRequest)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ NDIS_OID_REQUEST * Request, _In_ WDFCONTEXT Context);
NTSTATUS NETEXPORT(NetExAdapterDispatchPreprocessedDirectOid)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ NDIS_OID_REQUEST * Request, _In_ WDFCONTEXT Context);
void NETEXPORT(NetAdapterExtensionSetNdisPmCapabilities)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ CONST NET_ADAPTER_NDIS_PM_CAPABILITIES * Capabilities);
NTSTATUS NETEXPORT(NetAdapterInitAllocateContext)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _Inout_ NETADAPTER_INIT * AdapterInit, _In_ WDF_OBJECT_ATTRIBUTES * Attributes, _Outptr_opt_ void ** Context);
void * NETEXPORT(NetAdapterInitGetTypedContextWorker)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER_INIT * AdapterInit, _In_ CONST WDF_OBJECT_CONTEXT_TYPE_INFO * TypeInfo);
void NETEXPORT(NetAdapterOffloadSetTxChecksumCapabilities)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ const NET_ADAPTER_OFFLOAD_TX_CHECKSUM_CAPABILITIES * HardwareCapabilities);
BOOLEAN NETEXPORT(NetOffloadIsTxChecksumIPv4Enabled)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETOFFLOAD Offload);
BOOLEAN NETEXPORT(NetOffloadIsTxChecksumTcpEnabled)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETOFFLOAD Offload);
BOOLEAN NETEXPORT(NetOffloadIsTxChecksumUdpEnabled)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETOFFLOAD Offload);
void NETEXPORT(NetAdapterOffloadSetRxChecksumCapabilities)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ const NET_ADAPTER_OFFLOAD_RX_CHECKSUM_CAPABILITIES * Capabilities);
BOOLEAN NETEXPORT(NetOffloadIsRxChecksumIPv4Enabled)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETOFFLOAD Offload);
BOOLEAN NETEXPORT(NetOffloadIsRxChecksumTcpEnabled)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETOFFLOAD Offload);
BOOLEAN NETEXPORT(NetOffloadIsRxChecksumUdpEnabled)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETOFFLOAD Offload);
void NETEXPORT(NetAdapterOffloadSetGsoCapabilities)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ NET_ADAPTER_OFFLOAD_GSO_CAPABILITIES * HardwareCapabilities);
BOOLEAN NETEXPORT(NetOffloadIsLsoIPv4Enabled)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETOFFLOAD Offload);
BOOLEAN NETEXPORT(NetOffloadIsLsoIPv6Enabled)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETOFFLOAD Offload);
BOOLEAN NETEXPORT(NetOffloadIsUsoIPv4Enabled)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETOFFLOAD Offload);
BOOLEAN NETEXPORT(NetOffloadIsUsoIPv6Enabled)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETOFFLOAD Offload);
void NETEXPORT(NetAdapterOffloadSetRscCapabilities)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ NET_ADAPTER_OFFLOAD_RSC_CAPABILITIES * HardwareCapabilities);
BOOLEAN NETEXPORT(NetOffloadIsTcpRscIPv4Enabled)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETOFFLOAD Offload);
BOOLEAN NETEXPORT(NetOffloadIsTcpRscIPv6Enabled)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETOFFLOAD Offload);
BOOLEAN NETEXPORT(NetOffloadIsRscTcpTimestampOptionEnabled)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETOFFLOAD Offload);
void NETEXPORT(NetAdapterOffloadSetIeee8021qTagCapabilities)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ NET_ADAPTER_OFFLOAD_IEEE8021Q_TAG_CAPABILITIES * HardwareCapabilities);
void NETEXPORT(NetAdapterInitAddTxDemux)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER_INIT * AdapterInit, _In_ NET_ADAPTER_TX_DEMUX const * Demux);
NET_ADAPTER_TX_DEMUX const * NETEXPORT(NetAdapterGetTxPeerAddressDemux)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter);
NTSTATUS NETEXPORT(NetBufferQueueCreate)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETEXECUTIONCONTEXT ExecutionContext, _In_ NET_BUFFER_QUEUE_CONFIG const * Config, _In_opt_ WDF_OBJECT_ATTRIBUTES * Attributes, _Outptr_ NETBUFFERQUEUE * BufferQueue);
void NETEXPORT(NetBufferQueueGetExtension)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETBUFFERQUEUE BufferQueue, _In_ NET_EXTENSION_QUERY const * Query, _Out_ NET_EXTENSION * Extension);
NET_RING * NETEXPORT(NetBufferQueueGetRing)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETBUFFERQUEUE BufferQueue);
void NETEXPORT(NetDeviceInitSetResetCapabilities)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _Inout_ PWDFDEVICE_INIT DeviceInit, _In_ const NET_DEVICE_RESET_CAPABILITIES * Capabilities);
void NETEXPORT(NetDeviceStoreResetDiagnostics)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ WDFDEVICE Device, _In_ SIZE_T ResetDiagnosticsSize, _In_reads_bytes_(ResetDiagnosticsSize) const UINT8 * ResetDiagnosticsBuffer);
void NETEXPORT(NetDeviceRequestReset)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ WDFDEVICE Device);
NTSTATUS NETEXPORT(NetExecutionContextCreate)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ WDFDEVICE Device, _In_ NET_EXECUTION_CONTEXT_CONFIG const * Config, _In_opt_ WDF_OBJECT_ATTRIBUTES * ClientAttributes, _Out_ NETEXECUTIONCONTEXT * ExecutionContext);
NTSTATUS NETEXPORT(NetExecutionContextTaskCreate)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETEXECUTIONCONTEXT NetExecutionContextHandle, _In_opt_ WDF_OBJECT_ATTRIBUTES * ClientAttributes, _In_ NET_EXECUTION_CONTEXT_TASK_CONFIG * NetExecutionContextTaskConfig, _Out_ NETEXECUTIONCONTEXTTASK* NetExecutionContextTaskHandle);
void NETEXPORT(NetExecutionContextNotify)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETEXECUTIONCONTEXT ExecutionContext);
void NETEXPORT(NetExecutionContextTaskEnqueue)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETEXECUTIONCONTEXTTASK NetExecutionContextTaskHandle);
void NETEXPORT(NetExecutionContextTaskWaitCompletion)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _Inout_ NETEXECUTIONCONTEXTTASK NetExecutionContextTaskHandle);
NETADAPTER NETEXPORT(NetPowerOffloadGetAdapter)(_In_ PNET_DRIVER_GLOBALS DriverGlobals, _In_ NETPOWEROFFLOAD PowerOffload);
UINT8 NETEXPORT(NetTxQueueGetDemux8021p)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETPACKETQUEUE Queue);
void NETEXPORT(NetAdapterExtensionInitSetPowerPolicyCallbacks)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _Inout_ NETADAPTEREXT_INIT * AdapterExtensionInit, _In_ NET_ADAPTER_EXTENSION_POWER_POLICY_CALLBACKS * Callbacks);
void NETEXPORT(NetAdapterInitSetSelfManagedPowerReferences)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER_INIT * AdapterInit, BOOLEAN SelfManagedPowerReference);
NETADAPTER_INIT * NETEXPORT(NetAdapterLightweightInitAllocate)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ GUID const * NetworkInterfaceGuid);
void NETEXPORT(NetAdapterWifiDestroyPeerAddressDatapath)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ SIZE_T Demux);
void NETEXPORT(NetAdapterPauseOffloadCapabilities)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter);
void NETEXPORT(NetAdapterResumeOffloadCapabilities)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter);
NET_WAKE_REASON_TYPE NETEXPORT(NetAdapterQueryWakeReason)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter);
UINT8 NETEXPORT(NetTxQueueGetDemuxWmmInfo)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETPACKETQUEUE Queue);
NET_EUI48_ADDRESS NETEXPORT(NetTxQueueGetDemuxPeerAddress)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETPACKETQUEUE Queue);
BOOLEAN NETEXPORT(NetOffloadIsUdpRscEnabled)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETOFFLOAD Offload);
void NETEXPORT(NetAdapterCompleteOidRequest)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ NDIS_OID_REQUEST * Request, _In_ NDIS_STATUS Status);
NTSTATUS NETEXPORT(NetAdapterSetNative80211Attributes)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ NDIS_MINIPORT_ADAPTER_NATIVE_802_11_ATTRIBUTES * Attributes);
void NETEXPORT(NetAdapterIndicateMiniportStatus)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ NDIS_STATUS_INDICATION * NdisStatusIndication);
void NETEXPORT(NetAdapterWifiAddPeer)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ const NET_EUI48_ADDRESS * Address);
void NETEXPORT(NetAdapterWifiRemovePeer)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETADAPTER Adapter, _In_ const NET_EUI48_ADDRESS * Address);
void NETEXPORT(NetTxQueueGetDemuxPeerAddressV2)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ NETPACKETQUEUE Queue, _Out_ NET_EUI48_ADDRESS * Address);
ULONG NETEXPORT(NetDeviceGetSupportedDeviceResetTypes)(_In_ NET_DRIVER_GLOBALS * DriverGlobals, _In_ WDFDEVICE Device);
NTSTATUS NETEXPORT(NetMemoryCollectionCreate)(_In_ NET_DRIVER_GLOBALS * Globals, _In_ WDFDEVICE Device, _In_opt_ WDF_OBJECT_ATTRIBUTES * ClientAttributes, _In_ const NET_MEMORY_COLLECTION_CONFIG * MemoryCollectionConfiguration, _Out_ NETMEMORYCOLLECTION* MemoryCollection);
NTSTATUS NETEXPORT(NetMemoryCreate)(_In_ NET_DRIVER_GLOBALS * Globals, _In_ NETMEMORYCOLLECTION MemoryCollection, _In_ const NET_MEMORY_CONFIG * Configuration, _Out_ NET_MEMORY_ID * MemoryId);
void NETEXPORT(NetMemoryDestroy)(_In_ NET_DRIVER_GLOBALS * Globals, _In_ NETMEMORYCOLLECTION MemoryCollection, _In_ NET_MEMORY_ID MemoryId);
}

#ifdef NX_DYNAMICS_GENERATE_TABLE

typedef VOID (NTAPI * NX_CLIENT_FUNCTION)(VOID);

static NX_CLIENT_FUNCTION const NxClientFunctionTable[NetFunctionTableNumEntries] =
{
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterInitAllocate)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterInitFree)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterInitSetDatapathCallbacks)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterCreate)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterStart)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterStop)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterSetLinkLayerCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterSetLinkLayerMtuSize)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterPowerOffloadSetArpCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterPowerOffloadSetNSCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterWakeSetBitmapCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterWakeSetMediaChangeCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterWakeSetMagicPacketCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterWakeSetPacketFilterCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterSetDataPathCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterSetLinkState)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterGetNetLuid)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterOpenConfiguration)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterSetPermanentLinkLayerAddress)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterSetCurrentLinkLayerAddress)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterOffloadSetChecksumCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetOffloadIsChecksumIPv4Enabled)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetOffloadIsChecksumTcpEnabled)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetOffloadIsChecksumUdpEnabled)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterReportWakeReasonPacket)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterReportWakeReasonMediaChange)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterInitGetCreatedAdapter)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterExtensionInitAllocate)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterExtensionInitSetOidRequestPreprocessCallback)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterDispatchPreprocessedOidRequest)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterGetParent)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterGetLinkLayerMtuSize)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterExtensionInitSetNdisPmCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterWdmGetNdisHandle)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterDriverWdmGetHandle)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetConfigurationClose)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetConfigurationOpenSubConfiguration)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetConfigurationQueryUlong)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetConfigurationQueryString)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetConfigurationQueryMultiString)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetConfigurationQueryBinary)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetConfigurationQueryLinkLayerAddress)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetConfigurationAssignUlong)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetConfigurationAssignUnicodeString)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetConfigurationAssignMultiString)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetConfigurationAssignBinary)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetDeviceInitConfig)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetDeviceOpenConfiguration)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetDeviceInitSetPowerPolicyEventCallbacks)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetDeviceInitSetResetConfig)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetDeviceAssignSupportedOidList)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetPowerOffloadGetType)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetPowerOffloadGetArpParameters)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetPowerOffloadGetNSParameters)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetDeviceGetPowerOffloadList)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetPowerOffloadListGetCount)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetPowerOffloadListGetElement)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterSetReceiveScalingCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetRxQueueCreate)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetRxQueueNotifyMoreReceivedPacketsAvailable)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetRxQueueInitGetQueueId)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetRxQueueGetRingCollection)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetRxQueueGetExtension)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetTxQueueCreate)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetTxQueueNotifyMoreCompletedPacketsAvailable)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetTxQueueInitGetQueueId)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetTxQueueGetRingCollection)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetTxQueueGetExtension)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetWakeSourceGetType)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetWakeSourceGetAdapter)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetWakeSourceGetBitmapParameters)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetWakeSourceGetMediaChangeParameters)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetDeviceGetWakeSourceList)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetWakeSourceListGetCount)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetWakeSourceListGetElement)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterWakeSetEapolPacketCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterSetReceiveFilterCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetReceiveFilterGetPacketFilter)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetReceiveFilterGetMulticastAddressCount)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetReceiveFilterGetMulticastAddressList)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetDriverExtensionInitialize)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterExtensionInitSetDirectOidRequestPreprocessCallback)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetExAdapterInitSetDirectOidPreprocessCallback)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterExtensionInitSetTxPeerDemuxCallback)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterDispatchPreprocessedDirectOidRequest)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetExAdapterDispatchPreprocessedDirectOid)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterExtensionSetNdisPmCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterInitAllocateContext)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterInitGetTypedContextWorker)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterOffloadSetTxChecksumCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetOffloadIsTxChecksumIPv4Enabled)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetOffloadIsTxChecksumTcpEnabled)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetOffloadIsTxChecksumUdpEnabled)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterOffloadSetRxChecksumCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetOffloadIsRxChecksumIPv4Enabled)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetOffloadIsRxChecksumTcpEnabled)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetOffloadIsRxChecksumUdpEnabled)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterOffloadSetGsoCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetOffloadIsLsoIPv4Enabled)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetOffloadIsLsoIPv6Enabled)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetOffloadIsUsoIPv4Enabled)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetOffloadIsUsoIPv6Enabled)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterOffloadSetRscCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetOffloadIsTcpRscIPv4Enabled)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetOffloadIsTcpRscIPv6Enabled)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetOffloadIsRscTcpTimestampOptionEnabled)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterOffloadSetIeee8021qTagCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterInitAddTxDemux)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterGetTxPeerAddressDemux)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetBufferQueueCreate)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetBufferQueueGetExtension)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetBufferQueueGetRing)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetDeviceInitSetResetCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetDeviceStoreResetDiagnostics)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetDeviceRequestReset)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetExecutionContextCreate)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetExecutionContextTaskCreate)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetExecutionContextNotify)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetExecutionContextTaskEnqueue)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetExecutionContextTaskWaitCompletion)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetPowerOffloadGetAdapter)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetTxQueueGetDemux8021p)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterExtensionInitSetPowerPolicyCallbacks)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterInitSetSelfManagedPowerReferences)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterLightweightInitAllocate)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterWifiDestroyPeerAddressDatapath)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterPauseOffloadCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterResumeOffloadCapabilities)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterQueryWakeReason)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetTxQueueGetDemuxWmmInfo)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetTxQueueGetDemuxPeerAddress)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetOffloadIsUdpRscEnabled)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterCompleteOidRequest)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterSetNative80211Attributes)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterIndicateMiniportStatus)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterWifiAddPeer)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetAdapterWifiRemovePeer)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetTxQueueGetDemuxPeerAddressV2)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetDeviceGetSupportedDeviceResetTypes)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetMemoryCollectionCreate)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetMemoryCreate)),
    reinterpret_cast<NX_CLIENT_FUNCTION>(NETEXPORT(NetMemoryDestroy)),
};

static size_t NxClientStructureTable[NET_STRUCTURE_TABLE_NUM_ENTRIES] =
{
    sizeof(NET_ADAPTER_DATAPATH_CALLBACKS),
    sizeof(NET_ADAPTER_DMA_CAPABILITIES),
    sizeof(NET_ADAPTER_EXTENSION_POWER_POLICY_CALLBACKS),
    sizeof(NET_ADAPTER_LINK_LAYER_ADDRESS),
    sizeof(NET_ADAPTER_LINK_LAYER_CAPABILITIES),
    sizeof(NET_ADAPTER_LINK_STATE),
    sizeof(NET_ADAPTER_NDIS_PM_CAPABILITIES),
    sizeof(NET_ADAPTER_OFFLOAD_CHECKSUM_CAPABILITIES),
    sizeof(NET_ADAPTER_OFFLOAD_GSO_CAPABILITIES),
    sizeof(NET_ADAPTER_OFFLOAD_IEEE8021Q_TAG_CAPABILITIES),
    sizeof(NET_ADAPTER_OFFLOAD_RSC_CAPABILITIES),
    sizeof(NET_ADAPTER_OFFLOAD_RX_CHECKSUM_CAPABILITIES),
    sizeof(NET_ADAPTER_OFFLOAD_TX_CHECKSUM_CAPABILITIES),
    sizeof(NET_ADAPTER_POWER_OFFLOAD_ARP_CAPABILITIES),
    sizeof(NET_ADAPTER_POWER_OFFLOAD_NS_CAPABILITIES),
    sizeof(NET_ADAPTER_RECEIVE_FILTER_CAPABILITIES),
    sizeof(NET_ADAPTER_RECEIVE_SCALING_CAPABILITIES),
    sizeof(NET_ADAPTER_RECEIVE_SCALING_HASH_SECRET_KEY),
    sizeof(NET_ADAPTER_RECEIVE_SCALING_INDIRECTION_ENTRIES),
    sizeof(NET_ADAPTER_RECEIVE_SCALING_INDIRECTION_ENTRY),
    sizeof(NET_ADAPTER_RX_CAPABILITIES),
    sizeof(NET_ADAPTER_TX_CAPABILITIES),
    sizeof(NET_ADAPTER_TX_DEMUX),
    sizeof(NET_ADAPTER_WAKE_BITMAP_CAPABILITIES),
    sizeof(NET_ADAPTER_WAKE_EAPOL_PACKET_CAPABILITIES),
    sizeof(NET_ADAPTER_WAKE_MAGIC_PACKET_CAPABILITIES),
    sizeof(NET_ADAPTER_WAKE_MEDIA_CHANGE_CAPABILITIES),
    sizeof(NET_ADAPTER_WAKE_PACKET_FILTER_CAPABILITIES),
    sizeof(NET_ADAPTER_WAKE_REASON_PACKET),
    sizeof(NET_BUFFER_QUEUE_CONFIG),
    sizeof(NET_DEVICE_POWER_POLICY_EVENT_CALLBACKS),
    sizeof(NET_DEVICE_RESET_CAPABILITIES),
    sizeof(NET_DEVICE_RESET_CONFIG),
    sizeof(NET_DRIVER_EXTENSION_CONFIG),
    sizeof(NET_DRIVER_GLOBALS),
    sizeof(NET_EXECUTION_CONTEXT_CONFIG),
    sizeof(NET_EXECUTION_CONTEXT_TASK_CONFIG),
    sizeof(NET_EXTENSION_QUERY),
    sizeof(NET_PACKET_QUEUE_CONFIG),
    sizeof(NET_POWER_OFFLOAD_ARP_PARAMETERS),
    sizeof(NET_POWER_OFFLOAD_LIST),
    sizeof(NET_POWER_OFFLOAD_NS_PARAMETERS),
    sizeof(NET_RXQUEUE_BUFFER_LAYOUT_HINT),
    sizeof(NET_WAKE_SOURCE_BITMAP_PARAMETERS),
    sizeof(NET_WAKE_SOURCE_LIST),
    sizeof(NET_WAKE_SOURCE_MEDIA_CHANGE_PARAMETERS),
    sizeof(NET_MEMORY_COLLECTION_CONFIG),
    sizeof(NET_MEMORY_CONFIG),
};

static
NTSTATUS
NetBindClientHelper(
    _Inout_ WDF_CLASS_BIND_INFO * ClassInfo,
    _In_ ULONG MajorVersion,
    _In_ ULONG MinorVersion)
{
    if (ClassInfo->Size < sizeof(WDF_CLASS_BIND_INFO))
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (ClassInfo->Version.Major != MajorVersion)
    {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    ULONG functionCount = ClassInfo->FunctionTableCount;

    if (ClassInfo->Version.Minor > MinorVersion)
    {
        if (ClassInfo->Size < sizeof(WDF_CLASS_BIND_INFO2))
        {
            return STATUS_OBJECT_TYPE_MISMATCH;
        }

        auto classInfo2 = reinterpret_cast<WDF_CLASS_BIND_INFO2 *>(ClassInfo);

        if (classInfo2->MinimumVersionRequired == nullptr ||
            classInfo2->ClientVersionHigherThanFramework == nullptr ||
            classInfo2->FuncCountPtr == nullptr ||
            classInfo2->StructCountPtr == nullptr ||
            classInfo2->StructTable == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }

        if (*classInfo2->MinimumVersionRequired > MinorVersion ||
            *classInfo2->MinimumVersionRequired > ClassInfo->Version.Minor)
        {
            return STATUS_OBJECT_TYPE_MISMATCH;
        }

        *classInfo2->ClientVersionHigherThanFramework = TRUE;
        *classInfo2->FuncCountPtr = NetFunctionTableNumEntries;
        *classInfo2->StructCountPtr = NET_STRUCTURE_TABLE_NUM_ENTRIES;
        *classInfo2->StructTable = reinterpret_cast<size_t>(NxClientStructureTable);

        functionCount = min(functionCount, static_cast<ULONG>(NetFunctionTableNumEntries));
    }
    else if (functionCount > NetFunctionTableNumEntries)
    {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(ClassInfo->FunctionTable, NxClientFunctionTable, functionCount * sizeof(NX_CLIENT_FUNCTION));
    return STATUS_SUCCESS;
}

#endif
