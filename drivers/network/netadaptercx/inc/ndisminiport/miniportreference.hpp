/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Owned reference on an NDIS miniport adapter
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#include <wil/resource.h>
#include <ndiswdf.h>

using unique_miniport_reference = wil::unique_any<NDIS_HANDLE, decltype(&::NdisWdfMiniportDereference), ::NdisWdfMiniportDereference>;
