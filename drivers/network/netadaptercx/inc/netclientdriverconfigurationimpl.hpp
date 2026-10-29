/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Driver configuration knob queries of NetAdapterCx
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#include <netclientdriverconfigurationconstants.h>

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
DriverConfigurationInitialize(
    void);

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
NetClientQueryDriverConfigurationUlong(
    _In_ DRIVER_CONFIG_ENUM ConfigurationEnum);

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
NetClientQueryDriverConfigurationBoolean(
    _In_ DRIVER_CONFIG_ENUM ConfigurationEnum);
