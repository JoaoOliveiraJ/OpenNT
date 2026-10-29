/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Kernel references to execution contexts owned by user-mode drivers
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#include <ntosp.h>
#include <executioncontextdispatch.h>

NTSTATUS
ExecutionContextReferenceByHandle(
    _In_ HANDLE EcUmHandle,
    _Out_ NET_EXECUTION_CONTEXT * EcKmHandle)
{
    UNREFERENCED_PARAMETER(EcUmHandle);

    /* TODO: resolve execution contexts created by user-mode NetAdapterCx drivers */
    *EcKmHandle = nullptr;
    return STATUS_NOT_SUPPORTED;
}

void
ExecutionContextDereference(
    _In_ NET_EXECUTION_CONTEXT EcKmHandle)
{
    UNREFERENCED_PARAMETER(EcKmHandle);
}
