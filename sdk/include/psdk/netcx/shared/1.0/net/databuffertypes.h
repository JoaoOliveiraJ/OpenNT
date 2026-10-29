/*
 * PROJECT:     OpenNT DDK
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     NetAdapterCx shared data path definitions
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif.ing@outlook.com>
 */

#pragma once

#pragma region Desktop Family or OneCore Family
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP | WINAPI_PARTITION_SYSTEM)

EXTERN_C_START

typedef void * NET_MEMORY_ID;

typedef struct _NET_FRAGMENT_NET_MEMORY
{
    NET_MEMORY_ID
        NetMemoryId;

} NET_FRAGMENT_NET_MEMORY;

C_ASSERT(sizeof(NET_FRAGMENT_NET_MEMORY) == sizeof(NET_MEMORY_ID));

EXTERN_C_END

#define NET_FRAGMENT_EXTENSION_NET_MEMORY_NAME L"ms_fragment_netmemory"
#define NET_FRAGMENT_EXTENSION_NET_MEMORY_VERSION_1 1U

#endif
#pragma endregion
