/*
 * PROJECT:     OpenNT NDIS library
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * FILE:        drivers/network/ndis/ndis/60wdf.c
 * PURPOSE:     Private NDIS/WDF class-extension bridge used by NetAdapterCx.
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif.ing@outlook.com>
 */

#include "ndis6_internal.h"

#define NDIS6_WDF_TAG 'fWNn'

#ifdef _WIN64
C_ASSERT(sizeof(NDIS_WDF_ADD_DEVICE_INFO) == 24);
C_ASSERT(sizeof(NDIS_WDF_COMPLETE_ADD_PARAMS) == 88);
C_ASSERT(sizeof(NDIS_WDF_CX_CHARACTERISTICS) == 120);
#endif

static NTSTATUS
Ndis6WdfCompleteIrp(
    _In_ PIRP Irp,
    _In_ NTSTATUS Status)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static BOOLEAN
Ndis6WdfReferenceAdapter(
    _In_ PLOGICAL_ADAPTER Adapter)
{
    PNDIS6_ADAPTER_EXT Ext;
    KIRQL OldIrql;
    BOOLEAN Referenced = FALSE;

    if (Adapter == NULL || !Adapter->IsNdis6)
        return FALSE;

    Ext = NDIS6_EXT(Adapter);
    if (Ext == NULL || !Ext->IsWdfManaged)
        return FALSE;

    KeAcquireSpinLock(&Ext->WdfReferenceLock, &OldIrql);
    if (!Ext->WdfRemoving)
    {
        if (Ext->WdfReferenceCount++ == 0)
            KeClearEvent(&Ext->WdfReferenceDrainEvent);
        Referenced = TRUE;
    }
    KeReleaseSpinLock(&Ext->WdfReferenceLock, OldIrql);

    return Referenced;
}

static VOID
Ndis6WdfDereferenceAdapter(
    _In_ PLOGICAL_ADAPTER Adapter)
{
    PNDIS6_ADAPTER_EXT Ext;
    KIRQL OldIrql;

    if (Adapter == NULL || !Adapter->IsNdis6)
        return;

    Ext = NDIS6_EXT(Adapter);
    if (Ext == NULL || !Ext->IsWdfManaged)
        return;

    KeAcquireSpinLock(&Ext->WdfReferenceLock, &OldIrql);
    ASSERT(Ext->WdfReferenceCount > 0);
    if (--Ext->WdfReferenceCount == 0)
        KeSetEvent(&Ext->WdfReferenceDrainEvent, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&Ext->WdfReferenceLock, OldIrql);
}

static VOID
Ndis6WdfWaitForReferences(
    _In_ PNDIS6_ADAPTER_EXT Ext)
{
    KIRQL OldIrql;
    BOOLEAN Wait;

    KeAcquireSpinLock(&Ext->WdfReferenceLock, &OldIrql);
    Ext->WdfRemoving = TRUE;
    Wait = (Ext->WdfReferenceCount != 0);
    KeReleaseSpinLock(&Ext->WdfReferenceLock, OldIrql);

    if (Wait)
    {
        KeWaitForSingleObject(&Ext->WdfReferenceDrainEvent,
                              Executive,
                              KernelMode,
                              FALSE,
                              NULL);
    }
}

/* Default execution-context tunables, matching NetAdapterCx's own
 * g_staticEcKnobs (netcx/ec/lib/executioncontext.cpp). */
static NDIS6_WDF_EC_RUNTIME_KNOBS Ndis6WdfEcKnobs = {
    sizeof(NDIS6_WDF_EC_RUNTIME_KNOBS),
    NDIS6_WDF_EC_FLAG_RUN_DPC_FOR_FIRST_LOOP,
    0,          /* MaxTimeAtDispatch */
    0,          /* DispatchTimeWarning */
    0,          /* DispatchTimeWarningInterval */
    80,         /* DpcWatchdogTimerThreshold */
    8,          /* WorkerThreadPriority */
    { 64, 64 }, /* MaxPacketsSend */
    { 64, 64 }, /* MaxPacketsSendComplete */
    { 64, 64 }, /* MaxPacketsReceive */
    { 64, 64 }  /* MaxPacketsReceiveComplete */
};

static VOID
Ndis6WdfBuildCompleteAddParameters(
    _In_ PLOGICAL_ADAPTER Adapter,
    _Out_ NDIS_WDF_COMPLETE_ADD_PARAMS * Parameters)
{
    PNDIS6_ADAPTER_EXT Ext = NDIS6_EXT(Adapter);
    PUNICODE_STRING Name = &Adapter->NdisMiniportBlock.MiniportName;
    NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES Keywords;
    UNICODE_STRING GuidString;
    USHORT Index;

    RtlZeroMemory(Parameters, sizeof(*Parameters));
    RtlZeroMemory(&Keywords, sizeof(Keywords));
    Keywords.MediaType = NdisMedium802_3;
    Ndis6ApplyInfInterfaceKeywords(Adapter->NdisMiniportBlock.PhysicalDeviceObject, &Keywords);

    /* The canonical miniport name is \Device\{xxxxxxxx-....}. Feed the
     * per-interface GUID back to NetAdapterCx when that form is present. */
    for (Index = 0; Index < Name->Length / sizeof(WCHAR); Index++)
    {
        if (Name->Buffer[Index] == L'{')
        {
            GuidString.Buffer = &Name->Buffer[Index];
            GuidString.Length = Name->Length - Index * sizeof(WCHAR);
            GuidString.MaximumLength = GuidString.Length;
            if (NT_SUCCESS(RtlGUIDFromString(&GuidString,
                                             &Parameters->InterfaceGuid)))
            {
                break;
            }
        }
    }

    Parameters->NetLuid = Ext->NetLuid;
    Parameters->MediaType = Keywords.MediaType;
    Parameters->BaseName = *Name;
    for (Index = 0; Index < Name->Length / sizeof(WCHAR); Index++)
    {
        if (Name->Buffer[Index] == L'{')
        {
            Parameters->BaseName.Buffer = &Name->Buffer[Index];
            Parameters->BaseName.Length = Name->Length - Index * sizeof(WCHAR);
            Parameters->BaseName.MaximumLength = Parameters->BaseName.Length;
            break;
        }
    }
    Parameters->AdapterInstanceName = *Name;
    Parameters->DriverImageName = Ext->DriverBlock->DriverObject->DriverName;
    Parameters->ExecutionContextKnobs = &Ndis6WdfEcKnobs;
}

NTSTATUS
NTAPI
NdisWdfRegisterCx(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath,
    _In_ NDIS_WDF_CX_DRIVER_CONTEXT DriverContext,
    _In_ NDIS_WDF_CX_CHARACTERISTICS * Characteristics,
    _Out_ NDIS_WDF_CX_DRIVER * NdisWdfCxDriverHandle)
{
    PNDIS6_WDF_CX_DRIVER CxDriver;
    ULONG Size;

    UNREFERENCED_PARAMETER(RegistryPath);

    if (DriverObject == NULL || Characteristics == NULL ||
        NdisWdfCxDriverHandle == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    Size = Characteristics->Header.Size;
    if (Size < sizeof(NDIS_OBJECT_HEADER) ||
        Size > sizeof(NDIS_WDF_CX_CHARACTERISTICS))
    {
        return STATUS_INVALID_PARAMETER;
    }

    CxDriver = ExAllocatePoolWithTag(NonPagedPool,
                                     sizeof(*CxDriver),
                                     NDIS6_WDF_TAG);
    if (CxDriver == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(CxDriver, sizeof(*CxDriver));
    CxDriver->Signature = NDIS6_WDF_CX_SIGNATURE;
    CxDriver->DriverObject = DriverObject;
    CxDriver->DriverContext = DriverContext;
    RtlCopyMemory(&CxDriver->Characteristics, Characteristics, Size);

    *NdisWdfCxDriverHandle = (NDIS_WDF_CX_DRIVER)CxDriver;
    DbgPrint("NDIS6-WDF: registered NetAdapterCx callbacks (size=%lu)\n",
             Size);
    return STATUS_SUCCESS;
}

VOID
NTAPI
NdisWdfDeregisterCx(
    _In_ NDIS_WDF_CX_DRIVER NdisWdfCxDriverHandle)
{
    PNDIS6_WDF_CX_DRIVER CxDriver = (PNDIS6_WDF_CX_DRIVER)NdisWdfCxDriverHandle;

    if (CxDriver == NULL ||
        CxDriver->Signature != NDIS6_WDF_CX_SIGNATURE)
    {
        return;
    }

    InterlockedExchange(&CxDriver->Deregistering, TRUE);
    if (CxDriver->ClientCount != 0)
    {
        DbgPrint("NDIS6-WDF: refusing to free active Cx (%ld clients)\n",
                 CxDriver->ClientCount);
        return;
    }

    CxDriver->Signature = 0;
    ExFreePoolWithTag(CxDriver, NDIS6_WDF_TAG);
}

NDIS_STATUS
NTAPI
NdisWdfRegisterMiniportDriver(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath,
    _In_ NDIS_WDF_CX_DRIVER NdisWdfCxDriverHandle,
    _In_opt_ NDIS_HANDLE MiniportDriverContext,
    _In_ PNDIS_MINIPORT_DRIVER_CHARACTERISTICS Characteristics,
    _Out_ PNDIS_HANDLE NdisMiniportDriverHandle)
{
    PNDIS6_WDF_CX_DRIVER CxDriver = (PNDIS6_WDF_CX_DRIVER)NdisWdfCxDriverHandle;

    if (CxDriver == NULL ||
        CxDriver->Signature != NDIS6_WDF_CX_SIGNATURE ||
        CxDriver->Deregistering)
    {
        return NDIS_STATUS_INVALID_PARAMETER;
    }

    return Ndis6RegisterMiniportDriverInternal(
        DriverObject,
        RegistryPath,
        MiniportDriverContext,
        Characteristics,
        CxDriver,
        NULL,
        NdisMiniportDriverHandle);
}

NDIS_STATUS
NTAPI
NdisLWMRegisterMiniportDriver(
    _In_ NDIS_HANDLE MiniportDriverContext,
    _In_ NDIS_LWM_DRIVER_CHARACTERISTICS * Characteristics,
    _Out_ PNDIS_HANDLE NdisLwmDriverHandle)
{
    NDIS_MINIPORT_DRIVER_CHARACTERISTICS MiniportCharacteristics;

    if (Characteristics == NULL || NdisLwmDriverHandle == NULL)
        return NDIS_STATUS_INVALID_PARAMETER;

    *NdisLwmDriverHandle = NULL;

    if (Characteristics->Header.Type != NDIS_OBJECT_TYPE_LWM_DRIVER_CHARACTERISTICS ||
        Characteristics->Header.Revision == 0 ||
        Characteristics->Header.Size < NDIS_SIZEOF_LWM_DRIVER_CHARACTERISTICS_REVISION_1)
    {
        return NDIS_STATUS_BAD_CHARACTERISTICS;
    }

    RtlZeroMemory(&MiniportCharacteristics, sizeof(MiniportCharacteristics));
    MiniportCharacteristics.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS;
    MiniportCharacteristics.Header.Revision = NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_3;
    MiniportCharacteristics.Header.Size = NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_3;
    MiniportCharacteristics.MajorNdisVersion = Characteristics->MajorNdisVersion;
    MiniportCharacteristics.MinorNdisVersion = Characteristics->MinorNdisVersion;
    MiniportCharacteristics.MajorDriverVersion = Characteristics->MajorDriverVersion;
    MiniportCharacteristics.MinorDriverVersion = Characteristics->MinorDriverVersion;
    MiniportCharacteristics.Flags = Characteristics->Flags;
    MiniportCharacteristics.SetOptionsHandler = Characteristics->SetOptionsHandler;
    MiniportCharacteristics.PauseHandler = Characteristics->PauseHandler;
    MiniportCharacteristics.RestartHandler = Characteristics->RestartHandler;
    MiniportCharacteristics.OidRequestHandler = Characteristics->OidRequestHandler;
    MiniportCharacteristics.SendNetBufferListsHandler = Characteristics->SendNetBufferListsHandler;
    MiniportCharacteristics.ReturnNetBufferListsHandler = Characteristics->ReturnNetBufferListsHandler;
    MiniportCharacteristics.CancelSendHandler = Characteristics->CancelSendHandler;
    MiniportCharacteristics.CancelOidRequestHandler = Characteristics->CancelOidRequestHandler;
    MiniportCharacteristics.DirectOidRequestHandler = Characteristics->DirectOidRequestHandler;
    MiniportCharacteristics.CancelDirectOidRequestHandler = Characteristics->CancelDirectOidRequestHandler;
    MiniportCharacteristics.SynchronousOidRequestHandler = Characteristics->SynchronousOidRequestHandler;

    return Ndis6RegisterLwmMiniportDriver(&Characteristics->ServiceName,
                                          MiniportDriverContext,
                                          &MiniportCharacteristics,
                                          NdisLwmDriverHandle);
}

VOID
NTAPI
NdisLWMDeregisterMiniportDriver(
    _In_ NDIS_HANDLE NdisLwmDriverHandle)
{
    NdisMDeregisterMiniportDriver(NdisLwmDriverHandle);
}

NDIS_STATUS
NTAPI
NdisLWMInitializeNetworkInterface(
    _In_ NDIS_HANDLE NdisLwmDriverHandle,
    _In_ NDIS_HANDLE MiniportAdapterContext,
    _In_ GUID const * InterfaceGuid,
    _Out_ PNDIS_HANDLE NdisMiniportAdapterHandle)
{
    PNDIS6_DRIVER_BLOCK Block = (PNDIS6_DRIVER_BLOCK)NdisLwmDriverHandle;
    PLOGICAL_ADAPTER Adapter;
    NDIS_STATUS Status;

    if (NdisMiniportAdapterHandle == NULL)
        return NDIS_STATUS_INVALID_PARAMETER;

    *NdisMiniportAdapterHandle = NULL;
    if (Block == NULL || Block->Signature != NDIS6_DRIVER_BLOCK_SIGNATURE || !Block->IsLwm ||
        InterfaceGuid == NULL)
    {
        return NDIS_STATUS_INVALID_PARAMETER;
    }

    Status = Ndis6CreateLwmInstance(Block, InterfaceGuid, MiniportAdapterContext, &Adapter);
    if (Status == NDIS_STATUS_SUCCESS)
        *NdisMiniportAdapterHandle = (NDIS_HANDLE)Adapter;
    return Status;
}

static
VOID
NTAPI
Ndis6LwmStartWorker(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context)
{
    PLOGICAL_ADAPTER Adapter = Context;
    PNDIS6_ADAPTER_EXT Ext = NDIS6_EXT(Adapter);
    extern VOID Ndis6BindAllProtocolsToAdapter(PLOGICAL_ADAPTER);

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Ndis6AttachFiltersToAdapter(Adapter) == NDIS_STATUS_SUCCESS)
    {
        Ndis6BindAllProtocolsToAdapter(Adapter);
        if (Ndis6RestartDriverStack(Adapter) == NDIS_STATUS_SUCCESS)
            ndisQueueProtocolBinding();
    }
    else
    {
        DbgPrint("NDIS6: mandatory filter attach failed on a lightweight miniport\n");
    }

    KeSetEvent(&Ext->LwmStartDoneEvent, IO_NO_INCREMENT, FALSE);
}

NDIS_STATUS
NTAPI
NdisLWMStartNetworkInterface(
    _In_ NDIS_HANDLE NdisMiniportAdapterHandle)
{
    PLOGICAL_ADAPTER Adapter = NdisMiniportAdapterHandle;
    PNDIS6_ADAPTER_EXT Ext;

    if (Adapter == NULL || !Adapter->IsNdis6)
        return NDIS_STATUS_INVALID_PARAMETER;

    Ext = NDIS6_EXT(Adapter);
    if (Ext == NULL || Ext->DriverBlock == NULL || !Ext->DriverBlock->IsLwm)
        return NDIS_STATUS_INVALID_PARAMETER;

    if (Ext->Initialized || !Ext->RegistrationAttrsValid || !Ext->GeneralAttrsValid)
        return NDIS_STATUS_INVALID_DEVICE_REQUEST;

    if (Ext->LwmStartWorkItem == NULL)
    {
        Ext->LwmStartWorkItem = IoAllocateWorkItem(Ext->FunctionalDeviceObject);
        if (Ext->LwmStartWorkItem == NULL)
            return NDIS_STATUS_RESOURCES;
    }

    Ext->Initialized = TRUE;
    InterlockedExchange(&Ext->ProtocolBindingsClosing, 0);
    KeClearEvent(&Ext->LwmStartDoneEvent);
    IoQueueWorkItem(Ext->LwmStartWorkItem, Ndis6LwmStartWorker, DelayedWorkQueue, Adapter);
    return NDIS_STATUS_SUCCESS;
}

VOID
NTAPI
NdisLWMUninitializeNetworkInterface(
    _In_ NDIS_HANDLE NdisMiniportAdapterHandle)
{
    PLOGICAL_ADAPTER Adapter = NdisMiniportAdapterHandle;
    PNDIS6_ADAPTER_EXT Ext;

    if (Adapter == NULL || !Adapter->IsNdis6)
        return;

    Ext = NDIS6_EXT(Adapter);
    if (Ext == NULL || Ext->DriverBlock == NULL || !Ext->DriverBlock->IsLwm)
        return;

    KeWaitForSingleObject(&Ext->LwmStartDoneEvent, Executive, KernelMode, FALSE, NULL);
    if (Ext->Initialized)
    {
        Ndis6CallMiniportHaltEx(Adapter, NdisHaltDeviceDisabled);
        Ext->Initialized = FALSE;
    }
    Ndis6DestroyLogicalAdapter(Adapter);
}

NTSTATUS
NTAPI
NdisWdfPnPAddDevice(
    _In_ NDIS_WDF_ADD_DEVICE_INFO * AddDeviceInfo,
    _Out_ PNDIS_HANDLE NdisMiniportAdapterHandle)
{
    PNDIS6_DRIVER_BLOCK DriverBlock;
    PLOGICAL_ADAPTER Adapter;
    PNDIS6_WDF_CX_DRIVER CxDriver;
    NDIS_WDF_COMPLETE_ADD_PARAMS CompleteAdd;
    NDIS_STATUS Status;

    if (AddDeviceInfo == NULL || NdisMiniportAdapterHandle == NULL ||
        AddDeviceInfo->DriverObject == NULL ||
        AddDeviceInfo->PhysicalDeviceObject == NULL ||
        AddDeviceInfo->MiniportAdapterContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    DriverBlock = Ndis6FindDriverBlock(AddDeviceInfo->DriverObject);
    if (DriverBlock == NULL || !DriverBlock->IsWdfManaged)
        return STATUS_DEVICE_NOT_READY;

    Status = Ndis6CreateWdfLogicalAdapter(DriverBlock,
                                          AddDeviceInfo,
                                          &Adapter);
    if (!NT_SUCCESS(Status))
        return (NTSTATUS)Status;

    Status = Ndis6CallMiniportAddDevice(Adapter);
    if (Status != NDIS_STATUS_SUCCESS)
    {
        Ndis6DestroyLogicalAdapter(Adapter);
        return (NTSTATUS)Status;
    }

    CxDriver = DriverBlock->WdfCxDriver;
    Ndis6WdfBuildCompleteAddParameters(Adapter, &CompleteAdd);
    if (CxDriver->Characteristics.EvtCxMiniportCompleteAdd)
    {
        CxDriver->Characteristics.EvtCxMiniportCompleteAdd(
            AddDeviceInfo->MiniportAdapterContext,
            &CompleteAdd);
    }

    *NdisMiniportAdapterHandle = Adapter;
    DbgPrint("NDIS6-WDF: added miniport %p for PDO %p, FDO %p\n",
             Adapter,
             AddDeviceInfo->PhysicalDeviceObject,
             Adapter->NdisMiniportBlock.DeviceObject);
    return STATUS_SUCCESS;
}

PVOID
NTAPI
NdisWdfGetAdapterContextFromAdapterHandle(
    _In_ NDIS_HANDLE NdisMiniportAdapterHandle)
{
    PLOGICAL_ADAPTER Adapter = NdisMiniportAdapterHandle;
    PNDIS6_ADAPTER_EXT Ext;

    if (Adapter == NULL || !Adapter->IsNdis6)
        return NULL;

    Ext = NDIS6_EXT(Adapter);
    return (Ext && Ext->IsWdfManaged)
        ? Ext->MiniportAdapterContext
        : NULL;
}

NTSTATUS
NTAPI
NdisWdfPnpPowerEventHandler(
    _In_ NDIS_HANDLE NdisMiniportAdapterHandle,
    _In_ NdisWdfPnpPowerAction PnpAction,
    _In_ NdisWdfPnpPowerAction PowerAction)
{
    PLOGICAL_ADAPTER Adapter = NdisMiniportAdapterHandle;
    PNDIS6_ADAPTER_EXT Ext;
    NDIS_STATUS Status;

    UNREFERENCED_PARAMETER(PowerAction);

    if (Adapter == NULL)
        return STATUS_INVALID_PARAMETER;

    /* NetAdapterCx may report remove again from its destructor after NDIS
     * has already torn down the logical state. */
    if (!Adapter->IsNdis6)
        return (PnpAction == NdisWdfActionPnpRemove)
            ? STATUS_SUCCESS
            : STATUS_INVALID_DEVICE_STATE;

    Ext = NDIS6_EXT(Adapter);
    if (Ext == NULL || !Ext->IsWdfManaged)
        return STATUS_INVALID_DEVICE_STATE;

    switch (PnpAction)
    {
        case NdisWdfActionPnpStart:
            if (!Ext->Initialized)
            {
                if (!Ndis6HasMandatoryKeywords(Adapter->NdisMiniportBlock.PhysicalDeviceObject))
                    return STATUS_UNSUCCESSFUL;

                Status = Ndis6CallMiniportInitializeEx(Adapter);
                if (Status != NDIS_STATUS_SUCCESS)
                    return (NTSTATUS)Status;

                Ext->Initialized = TRUE;
                InterlockedExchange(&Ext->ProtocolBindingsClosing, 0);
                if (Ext->DriverBlock->WdfCxDriver->Characteristics.EvtCxDeviceStartComplete)
                {
                    Ext->DriverBlock->WdfCxDriver->Characteristics.EvtCxDeviceStartComplete(
                        Ext->MiniportAdapterContext);
                }
                Ndis6SetNetInterfaceState(Adapter, TRUE);
            }
            return STATUS_SUCCESS;

        case NdisWdfActionPnpStop:
            if (Ext->Initialized)
            {
                /* FIXME: a rebalance stop reports NdisHaltDeviceDisabled, not NdisHaltDeviceStopped */
                Ndis6CallMiniportHaltEx(Adapter, Ext->WdfSurpriseRemoved ? NdisHaltDeviceSurpriseRemoved : NdisHaltDeviceDisabled);
                Ext->Initialized = FALSE;
                Ext->WdfBindingsStarted = FALSE;
            }
            return STATUS_SUCCESS;

        case NdisWdfActionPowerDx:
        case NdisWdfActionPowerDxFinal:
        case NdisWdfActionPowerDxOnSystemSx:
        case NdisWdfActionPowerDxOnSystemShutdown:
            return (NTSTATUS)Ndis6PauseDriverStack(Adapter);

        case NdisWdfActionPowerD0:
        case NdisWdfActionPowerD0Implicit:
        {
            return (NTSTATUS)Ndis6RestartDriverStack(Adapter);
        }

        case NdisWdfActionPnpSurpriseRemove:
            Ext->WdfSurpriseRemoved = TRUE;
            Ndis6NotifyMiniportDevicePnPEvent(Ext, NdisDevicePnPEventSurpriseRemoved);
            (VOID)Ndis6PauseDriverStack(Adapter);
            return STATUS_SUCCESS;

        case NdisWdfActionPnpRemove:
            Ndis6WdfWaitForReferences(Ext);
            if (Ext->Initialized)
            {
                Ndis6CallMiniportHaltEx(Adapter, Ext->WdfSurpriseRemoved ? NdisHaltDeviceSurpriseRemoved : NdisHaltDeviceDisabled);
                Ext->Initialized = FALSE;
            }
            Ndis6DestroyLogicalAdapter(Adapter);
            return STATUS_SUCCESS;

        case NdisWdfActionPnpQueryStop:
        case NdisWdfActionPnpCancelStop:
        case NdisWdfActionPnpQueryRemove:
        case NdisWdfActionPnpCancelRemove:
        case NdisWdfActionStartPowerManagement:
        case NdisWdfActionStopPowerManagement:
        case NdisWdfActionPreReleaseHardware:
        case NdisWdfActionPostReleaseHardware:
        case NdisWdfActionPnpRebalance:
        case NdisWdfActionDeviceObjectCleanup:
        case NdisWdfActionPowerNone:
        default:
            return STATUS_SUCCESS;
    }
}

VOID
NTAPI
NdisWdfMiniportStarted(
    _In_ NDIS_HANDLE NdisMiniportAdapterHandle)
{
    PLOGICAL_ADAPTER Adapter = NdisMiniportAdapterHandle;
    PNDIS6_ADAPTER_EXT Ext;

    if (Adapter == NULL || !Adapter->IsNdis6)
        return;

    Ext = NDIS6_EXT(Adapter);
    if (Ext == NULL || !Ext->IsWdfManaged || !Ext->Initialized)
        return;

    if (!Ext->WdfBindingsStarted)
    {
        NDIS_STATUS Status;
        extern VOID Ndis6BindAllProtocolsToAdapter(PLOGICAL_ADAPTER);

        Status = Ndis6AttachFiltersToAdapter(Adapter);
        if (Status != NDIS_STATUS_SUCCESS)
        {
            DbgPrint("NDIS6-WDF: mandatory filter attach failed 0x%08lx\n", (ULONG)Status);
            return;
        }
        Ndis6BindAllProtocolsToAdapter(Adapter);
        Ext->WdfBindingsStarted = TRUE;
    }

    if (Ndis6RestartDriverStack(Adapter) == NDIS_STATUS_SUCCESS)
        ndisQueueProtocolBinding();
}

VOID
NTAPI
NdisWdfMiniportDataPathStart(
    _In_ NDIS_HANDLE NdisMiniportAdapterHandle)
{
    PLOGICAL_ADAPTER Adapter = NdisMiniportAdapterHandle;

    if (Adapter && Adapter->IsNdis6)
    {
        (VOID)Ndis6RestartDriverStack(Adapter);
    }
}

VOID
NTAPI
NdisWdfMiniportSetPower(
    _In_ NDIS_HANDLE NdisMiniportAdapterHandle,
    _In_ POWER_ACTION SystemPowerAction,
    _In_ DEVICE_POWER_STATE DevicePowerState)
{
    PLOGICAL_ADAPTER Adapter = NdisMiniportAdapterHandle;
    PNDIS6_ADAPTER_EXT Ext;
    NDIS_STATUS Status;

    UNREFERENCED_PARAMETER(SystemPowerAction);

    if (Adapter == NULL || !Adapter->IsNdis6)
        return;

    Ext = NDIS6_EXT(Adapter);
    if (Ext == NULL || !Ext->IsWdfManaged || !Ext->Initialized)
        return;

    /* NetAdapterCx stops/starts its packet queues around this callback. This
     * NDIS entry point supplies the separate device-power notification; it
     * must not manufacture another Pause/Restart transition. */
    Status = Ndis6SetMiniportDevicePowerState(Ext, DevicePowerState);
    if (Status == NDIS_STATUS_SUCCESS)
        Ext->DevicePowerState = DevicePowerState;
    else
        DbgPrint("NDIS6/WDF: OID_PNP_SET_POWER D%u failed 0x%08lx\n", (ULONG)DevicePowerState - (ULONG)PowerDeviceD0, (ULONG)Status);
}

BOOLEAN
NTAPI
NdisWdfMiniportTryReference(
    _In_ NDIS_HANDLE NdisMiniportAdapterHandle)
{
    return Ndis6WdfReferenceAdapter(NdisMiniportAdapterHandle);
}

VOID
NTAPI
NdisWdfMiniportDereference(
    _In_ NDIS_HANDLE NdisMiniportAdapterHandle)
{
    Ndis6WdfDereferenceAdapter(NdisMiniportAdapterHandle);
}

VOID
NTAPI
NdisWdfAsyncPowerReferenceCompleteNotification(
    _In_ NDIS_HANDLE NdisMiniportAdapterHandle,
    _In_ NTSTATUS Status)
{
    UNREFERENCED_PARAMETER(NdisMiniportAdapterHandle);
    UNREFERENCED_PARAMETER(Status);
}

VOID
NTAPI
NdisWdfNotifyWmiAdapterArrival(
    _In_ NDIS_HANDLE NdisMiniportAdapterHandle)
{
    UNREFERENCED_PARAMETER(NdisMiniportAdapterHandle);
}

NTSTATUS
NTAPI
NdisWdfCreateIrpHandler(
    _In_ NDIS_HANDLE NdisMiniportAdapterHandle,
    _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack;

    if (!Ndis6WdfReferenceAdapter(NdisMiniportAdapterHandle))
        return Ndis6WdfCompleteIrp(Irp, STATUS_DELETE_PENDING);

    Stack = IoGetCurrentIrpStackLocation(Irp);
    if (Stack->FileObject == NULL)
    {
        Ndis6WdfDereferenceAdapter(NdisMiniportAdapterHandle);
        return Ndis6WdfCompleteIrp(Irp, STATUS_INVALID_PARAMETER);
    }

    Stack->FileObject->FsContext = NdisMiniportAdapterHandle;
    return Ndis6WdfCompleteIrp(Irp, STATUS_SUCCESS);
}

NTSTATUS
NTAPI
NdisWdfCloseIrpHandler(
    _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PLOGICAL_ADAPTER Adapter = NULL;

    if (Stack->FileObject)
    {
        Adapter = Stack->FileObject->FsContext;
        Stack->FileObject->FsContext = NULL;
    }

    if (Adapter)
        Ndis6WdfDereferenceAdapter(Adapter);

    return Ndis6WdfCompleteIrp(Irp, STATUS_SUCCESS);
}

NTSTATUS
NTAPI
NdisWdfDeviceControlIrpHandler(
    _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;

    if (Stack->DeviceObject &&
        Ndis6TryDispatchAdapterFdoIrp(Stack->DeviceObject, Irp, &Status))
    {
        return Status;
    }

    return Ndis6WdfCompleteIrp(Irp, STATUS_NOT_SUPPORTED);
}

NTSTATUS
NTAPI
NdisWdfDeviceInternalControlIrpHandler(
    _Inout_ PIRP Irp)
{
    return Ndis6WdfCompleteIrp(Irp, STATUS_NOT_SUPPORTED);
}

VOID
NTAPI
NdisWdfGetGuidToOidMap(
    _In_reads_(OidCount) PNDIS_OID OidList,
    _In_ USHORT OidCount,
    _Out_writes_opt_(*GuidCount) PNDIS_GUID GuidMap,
    _Inout_ PUSHORT GuidCount)
{
    USHORT Index;
    USHORT Capacity;

    if (GuidCount == NULL)
        return;

    Capacity = GuidMap ? *GuidCount : 0;
    *GuidCount = OidCount;

    if (GuidMap == NULL || OidList == NULL)
        return;

    for (Index = 0; Index < OidCount && Index < Capacity; Index++)
    {
        RtlZeroMemory(&GuidMap[Index], sizeof(GuidMap[Index]));
        GuidMap[Index].Guid.Data1 = OidList[Index];
        GuidMap[Index].Guid.Data2 = 0x4e44;
        GuidMap[Index].Guid.Data3 = 0x4953;
        GuidMap[Index].Guid.Data4[0] = 0x57;
        GuidMap[Index].Guid.Data4[1] = 0x44;
        GuidMap[Index].Oid = OidList[Index];
        GuidMap[Index].Size = sizeof(ULONG);
        GuidMap[Index].Flags = NDIS_GUID_TO_OID;
    }
}

NTSTATUS
NTAPI
NdisWdfQueryAllData(
    _In_ NDIS_HANDLE NdisMiniportAdapterHandle,
    _In_ PNDIS_GUID NdisGuid,
    _In_ PGUID Guid,
    _Inout_updates_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG ReturnSize)
{
    UNREFERENCED_PARAMETER(NdisMiniportAdapterHandle);
    UNREFERENCED_PARAMETER(NdisGuid);
    UNREFERENCED_PARAMETER(Guid);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(BufferSize);
    if (ReturnSize)
        *ReturnSize = 0;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
NdisWdfQuerySingleInstance(
    _In_ NDIS_HANDLE NdisMiniportAdapterHandle,
    _In_ PNDIS_GUID NdisGuid,
    _Inout_ PVOID Wnode,
    _In_ ULONG BufferSize,
    _Out_ PULONG ReturnSize)
{
    UNREFERENCED_PARAMETER(NdisMiniportAdapterHandle);
    UNREFERENCED_PARAMETER(NdisGuid);
    UNREFERENCED_PARAMETER(Wnode);
    UNREFERENCED_PARAMETER(BufferSize);
    if (ReturnSize)
        *ReturnSize = 0;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
NdisWdfChangeSingleInstance(
    _In_ NDIS_HANDLE NdisMiniportAdapterHandle,
    _In_ PNDIS_GUID NdisGuid,
    _Inout_ PVOID Wnode)
{
    UNREFERENCED_PARAMETER(NdisMiniportAdapterHandle);
    UNREFERENCED_PARAMETER(NdisGuid);
    UNREFERENCED_PARAMETER(Wnode);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
NdisWdfExecuteMethod(
    _In_ NDIS_HANDLE NdisMiniportAdapterHandle,
    _In_ PNDIS_GUID NdisGuid,
    _Inout_ PVOID Wnode,
    _In_ ULONG BufferSize,
    _Out_ PULONG ReturnSize)
{
    return NdisWdfQuerySingleInstance(NdisMiniportAdapterHandle,
                                      NdisGuid,
                                      Wnode,
                                      BufferSize,
                                      ReturnSize);
}

VOID
NTAPI
NdisWdfReadConfiguration(
    _Out_ PNDIS_STATUS Status,
    _Out_ PNDIS_CONFIGURATION_PARAMETER* ParameterValue,
    _In_ NDIS_HANDLE ConfigurationHandle,
    _In_ PNDIS_STRING Keyword,
    _In_ NDIS_PARAMETER_TYPE ParameterType)
{
    NdisReadConfiguration(Status,
                          ParameterValue,
                          ConfigurationHandle,
                          Keyword,
                          ParameterType);
}
