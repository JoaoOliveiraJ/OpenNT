/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Module loader that resolves the execution context module built into NetAdapterCx
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#include <kloadertypes.h>
#include <executioncontextdispatch.h>

NET_EXECUTION_CONTEXT_DISPATCH const *
GetExecutionContextDispatch(
    void);

inline
NTSTATUS
KLoaderReferenceModule(
    _In_ KLOADER_REFERENCE_MODULE_CONFIG const * Config,
    _Out_ KLOADER_MODULE_REFERENCE * Module)
{
    *Module = nullptr;

    if (Config->Size < sizeof(*Config))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (!IsEqualGUID(Config->ModuleID, EXECUTION_CONTEXT_MODULE_ID))
    {
        return STATUS_NOT_FOUND;
    }

    *Module = reinterpret_cast<KLOADER_MODULE_REFERENCE>(
        const_cast<NET_EXECUTION_CONTEXT_DISPATCH *>(GetExecutionContextDispatch()));
    return STATUS_SUCCESS;
}

inline
NTSTATUS
KLoaderQueryDispatchTable(
    _In_ KLOADER_MODULE_REFERENCE Module,
    _In_ GUID const * DispatchTableID,
    _Out_ KLOADER_DISPATCH_TABLE const ** DispatchTable)
{
    *DispatchTable = nullptr;

    if (Module == nullptr || !IsEqualGUID(*DispatchTableID, EXECUTION_CONTEXT_DISPATCH_TABLE_ID))
    {
        return STATUS_NOT_FOUND;
    }

    *DispatchTable = reinterpret_cast<KLOADER_DISPATCH_TABLE const *>(GetExecutionContextDispatch());
    return STATUS_SUCCESS;
}

inline
void
KLoaderDereferenceModule(
    _In_ KLOADER_MODULE_REFERENCE Module)
{
    UNREFERENCED_PARAMETER(Module);
}
