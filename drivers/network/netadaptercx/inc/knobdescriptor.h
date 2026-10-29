/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Configuration knob descriptors
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

enum class ConfigKnobFlag : ULONG
{
    OnlyUpdateOnceAtBoot = 0,
    Uint32Datatype = 0,
    BooleanDatatype = 2,
    Uint64Datatype = 4,
    AllowDynamicUpdate = 32,
    MustBePowerOfTwo = 64,
};

DEFINE_ENUM_FLAG_OPERATORS(ConfigKnobFlag);

enum class ConfigKnobSource : ULONG
{
    Unknown = 0,
    DefaultValue = 1,
    DefaultStore = 2,
    OverrideStore = 3,
    EphemeralOverride = 4,
};

typedef enum _CONFIG_KNOB_NAMESPACE_TYPE
{
    ConfigKnobNamespaceNdisGlobal = 0,
    ConfigKnobNamespaceNetworkInterface = 1,
    ConfigKnobNamespaceExecutionContext = 2,
    /* FIXME: value unverified, the 22621 symbols end at ConfigKnobNamespaceExecutionContext */
    ConfigKnobNamespaceCpuExecutionContext = 3,
} CONFIG_KNOB_NAMESPACE_TYPE;

typedef struct _CONFIG_KNOB_NAMESPACE
{
    CONFIG_KNOB_NAMESPACE_TYPE NamespaceType;
    GUID ObjectId;
} CONFIG_KNOB_NAMESPACE;

struct KnobDescriptor
{
    wchar_t const * Name;
    void * Value;
    ULONG64 DefaultValue;
    ConfigKnobFlag Flags;
    ULONG64 MinimumValue;
    ULONG64 MaximumValue;

    bool
    IsUint64(
        void) const
    {
        return WI_IsFlagSet(Flags, ConfigKnobFlag::Uint64Datatype);
    }

    bool
    IsBoolean(
        void) const
    {
        return WI_IsFlagSet(Flags, ConfigKnobFlag::BooleanDatatype);
    }

    ULONG64
    GetCurrentValue(
        void) const
    {
        if (IsUint64())
        {
            return ReadNoFence64(static_cast<LONG64 const volatile *>(Value));
        }

        return static_cast<ULONG>(ReadNoFence(static_cast<LONG const volatile *>(Value)));
    }

    void
    SetCurrentValue(
        _In_ ULONG64 NewValue) const
    {
        if (IsUint64())
        {
            WriteNoFence64(static_cast<LONG64 volatile *>(Value), static_cast<LONG64>(NewValue));
            return;
        }

        WriteNoFence(static_cast<LONG volatile *>(Value), static_cast<LONG>(NewValue));
    }
};

static_assert(sizeof(KnobDescriptor) == 48, "KnobDescriptor size differs from the 22621 symbols");
