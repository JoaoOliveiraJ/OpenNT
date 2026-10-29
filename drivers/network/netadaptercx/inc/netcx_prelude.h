/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     First header of every NetAdapterCx translation unit (passed with -include)
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#include <ntifs.h>
#include <ntintsafe.h>

#define NETCX_ADAPTER_2
#include <ndis.h>
#include <net/extension.h>
#include <net/fragment.h>
#include <net/packet.h>
#include <net/ring.h>
#include <net/ringcollection.h>
#undef NETCX_ADAPTER_2

#include <netcx_wpp.h>
