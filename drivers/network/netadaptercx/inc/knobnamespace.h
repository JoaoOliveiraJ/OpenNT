/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Configuration knob namespaces
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#include <knobdescriptor.h>

typedef
BOOLEAN
KNOB_VALIDATE_ROUTINE(
    _In_ void * Context,
    _In_ KnobDescriptor const * Knob,
    _Inout_ ULONG64 & NewValue);

typedef
NTSTATUS
KNOB_UPDATE_ROUTINE(
    _In_ void * Context,
    _In_ KnobDescriptor const * Knob,
    _In_ ULONG64 NewValue);

class KnobNamespace
{
public:

    static
    void
    InitializeSubsystem(
        void)
    {
    }

    KnobNamespace(
        void) = default;

    KnobNamespace(KnobNamespace const &) = delete;
    KnobNamespace & operator=(KnobNamespace const &) = delete;

    _IRQL_requires_(PASSIVE_LEVEL)
    void
    Initialize(
        _In_opt_ DRIVER_OBJECT const * DriverObject,
        _In_ CONFIG_KNOB_NAMESPACE const * Id)
    {
        m_driverObject = DriverObject;
        m_id = *Id;
    }

    _IRQL_requires_(PASSIVE_LEVEL)
    NTSTATUS
    AddKnobCollection(
        _In_reads_(Count) KnobDescriptor const * Knobs,
        _In_ SIZE_T Count,
        _In_opt_ KNOB_VALIDATE_ROUTINE * ValidateRoutine,
        _In_opt_ KNOB_UPDATE_ROUTINE * UpdateRoutine,
        _In_opt_ void * Context)
    {
        UNREFERENCED_PARAMETER(ValidateRoutine);
        UNREFERENCED_PARAMETER(UpdateRoutine);
        UNREFERENCED_PARAMETER(Context);

        for (SIZE_T i = 0; i < Count; i++)
        {
            if (Knobs[i].IsBoolean())
            {
                /* TODO: BooleanDatatype knobs (storage width unverified) */
                return STATUS_NOT_SUPPORTED;
            }
        }

        /* TODO: read the NetworkSetup2 knob store and take dynamic updates; defaults only */
        for (SIZE_T i = 0; i < Count; i++)
        {
            Knobs[i].SetCurrentValue(Knobs[i].DefaultValue);
        }

        return STATUS_SUCCESS;
    }

private:

    DRIVER_OBJECT const *
        m_driverObject = nullptr;

    CONFIG_KNOB_NAMESPACE
        m_id = {};
};
