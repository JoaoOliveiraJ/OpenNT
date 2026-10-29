/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     IRP plumbing NetAdapterCx uses between WDF preprocessing and NDIS
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#include <ndiswdf.h>

class IrpHandler
{
public:

    _IRQL_requires_(PASSIVE_LEVEL)
    NTSTATUS
    AssingIrpPreprocessCallback(
        _In_ WDFCXDEVICE_INIT * CxDeviceInit,
        _In_ PFN_WDFCXDEVICE_WDM_IRP_PREPROCESS PreprocessRoutine,
        _In_ UCHAR MajorFunction,
        _In_reads_opt_(NumMinorFunctions) UCHAR * MinorFunctions,
        _In_ ULONG NumMinorFunctions)
    {
        return WdfCxDeviceInitAssignWdmIrpPreprocessCallback(
            CxDeviceInit,
            PreprocessRoutine,
            MajorFunction,
            MinorFunctions,
            NumMinorFunctions);
    }

    _IRQL_requires_(PASSIVE_LEVEL)
    NTSTATUS
    Initialize(
        _In_ WDFDEVICE_INIT * DeviceInit)
    {
        UNREFERENCED_PARAMETER(DeviceInit);
        return STATUS_SUCCESS;
    }

    void
    SetWdfDevice(
        _In_ WDFDEVICE Device)
    {
        m_device = Device;
    }

    IO_STACK_LOCATION *
    IoGetCurrentIrpStackLocation(
        _In_ IRP * Irp) const
    {
        return ::IoGetCurrentIrpStackLocation(Irp);
    }

    void
    IoSkipCurrentIrpStackLocation(
        _Inout_ IRP * Irp) const
    {
        ::IoSkipCurrentIrpStackLocation(Irp);
    }

    NTSTATUS
    IoDispatchIrp(
        _Inout_ IRP * Irp,
        _In_ WDFCONTEXT DispatchContext) const
    {
        return WdfDeviceWdmDispatchIrp(m_device, Irp, DispatchContext);
    }

    void
    IoCompleteIrp(
        _Inout_ IRP * Irp,
        _In_ CCHAR PriorityBoost,
        _In_ WDFCONTEXT DispatchContext) const
    {
        UNREFERENCED_PARAMETER(DispatchContext);
        IoCompleteRequest(Irp, PriorityBoost);
    }

    template <typename TAdapter>
    NTSTATUS
    NdisWdfCreateIrpHandler(
        _In_ TAdapter * Adapter,
        _Inout_ IRP * Irp,
        _In_ WDFCONTEXT DispatchContext) const
    {
        UNREFERENCED_PARAMETER(DispatchContext);
        NDIS_HANDLE const ndisAdapterHandle = Adapter->GetNdisHandle();
        NTSTATUS const status = ::NdisWdfCreateIrpHandler(ndisAdapterHandle, Irp);
        NdisWdfMiniportDereference(ndisAdapterHandle);
        return status;
    }

    NTSTATUS
    NdisWdfCloseIrpHandler(
        _Inout_ IRP * Irp,
        _In_ WDFCONTEXT DispatchContext) const
    {
        UNREFERENCED_PARAMETER(DispatchContext);
        return ::NdisWdfCloseIrpHandler(Irp);
    }

    NTSTATUS
    NdisWdfDeviceControlIrpHandler(
        _Inout_ IRP * Irp,
        _In_ WDFCONTEXT DispatchContext) const
    {
        UNREFERENCED_PARAMETER(DispatchContext);
        return ::NdisWdfDeviceControlIrpHandler(Irp);
    }

    NTSTATUS
    NdisWdfDeviceInternalControlIrpHandler(
        _Inout_ IRP * Irp,
        _In_ WDFCONTEXT DispatchContext) const
    {
        UNREFERENCED_PARAMETER(DispatchContext);
        return ::NdisWdfDeviceInternalControlIrpHandler(Irp);
    }

    ULONG_PTR
    GetWmiProviderId(
        void) const
    {
        return reinterpret_cast<ULONG_PTR>(WdfDeviceWdmGetDeviceObject(m_device));
    }

    NTSTATUS
    GetGuidToOidMap(
        _In_reads_(OidCount) PNDIS_OID OidList,
        _In_ USHORT OidCount,
        _Out_writes_opt_(*GuidCount) PNDIS_GUID GuidMap,
        _Inout_ PUSHORT GuidCount) const
    {
        ::NdisWdfGetGuidToOidMap(OidList, OidCount, GuidMap, GuidCount);
        return STATUS_SUCCESS;
    }

    NTSTATUS
    IoWMIWriteEvent(
        _In_ PVOID WnodeEventItem) const
    {
        return ::IoWMIWriteEvent(WnodeEventItem);
    }

private:

    WDFDEVICE m_device = WDF_NO_HANDLE;
};
