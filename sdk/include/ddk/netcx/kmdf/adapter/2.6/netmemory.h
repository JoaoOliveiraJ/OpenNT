/*
 * PROJECT:     OpenNT DDK
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     NetAdapterCx 2.6 pre-registered receive memory interface
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#ifndef _NETMEMORY_2_6_H_
#define _NETMEMORY_2_6_H_

#ifndef WDF_EXTERN_C
  #ifdef __cplusplus
    #define WDF_EXTERN_C       extern "C"
    #define WDF_EXTERN_C_START extern "C" {
    #define WDF_EXTERN_C_END   }
  #else
    #define WDF_EXTERN_C
    #define WDF_EXTERN_C_START
    #define WDF_EXTERN_C_END
  #endif
#endif

WDF_EXTERN_C_START

typedef struct _NET_MEMORY_CONFIG
{
    ULONG Size;
    void * BufferAddress;
    SIZE_T BufferLength;
} NET_MEMORY_CONFIG;

inline
void
NET_MEMORY_CONFIG_INIT(
    _Out_ NET_MEMORY_CONFIG * NetMemoryConfig,
    _In_ void * BufferAddress,
    _In_ SIZE_T BufferLength
)
{
    RtlZeroMemory(NetMemoryConfig, sizeof(*NetMemoryConfig));
    NetMemoryConfig->Size = sizeof(*NetMemoryConfig);
    NetMemoryConfig->BufferAddress = BufferAddress;
    NetMemoryConfig->BufferLength = BufferLength;
}

typedef struct _NET_MEMORY_COLLECTION_CONFIG
{
    ULONG Size;
    SIZE_T BuffersCountHint;
} NET_MEMORY_COLLECTION_CONFIG;

inline
void
NET_MEMORY_COLLECTION_CONFIG_INIT(
    _Out_ NET_MEMORY_COLLECTION_CONFIG * NetMemoryCollectionConfig,
    _In_ SIZE_T BuffersCountHint
)
{
    RtlZeroMemory(NetMemoryCollectionConfig, sizeof(*NetMemoryCollectionConfig));
    NetMemoryCollectionConfig->Size = sizeof(*NetMemoryCollectionConfig);
    NetMemoryCollectionConfig->BuffersCountHint = BuffersCountHint;
}

typedef
_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
WDFAPI
NTSTATUS
(NTAPI *PFN_NETMEMORYCOLLECTIONCREATE)(
    _In_
    PNET_DRIVER_GLOBALS DriverGlobals,
    _In_
    WDFDEVICE Device,
    _In_opt_
    WDF_OBJECT_ATTRIBUTES* ClientAttributes,
    _In_
    CONST NET_MEMORY_COLLECTION_CONFIG* MemoryCollectionConfiguration,
    _Out_
    NETMEMORYCOLLECTION* MemoryCollection
    );

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
FORCEINLINE
NTSTATUS
NetMemoryCollectionCreate(
    _In_
    WDFDEVICE Device,
    _In_opt_
    WDF_OBJECT_ATTRIBUTES* ClientAttributes,
    _In_
    CONST NET_MEMORY_COLLECTION_CONFIG* MemoryCollectionConfiguration,
    _Out_
    NETMEMORYCOLLECTION* MemoryCollection
    )
{
    return ((PFN_NETMEMORYCOLLECTIONCREATE) NetFunctions[NetMemoryCollectionCreateTableIndex])(NetDriverGlobals, Device, ClientAttributes, MemoryCollectionConfiguration, MemoryCollection);
}

typedef
_IRQL_requires_(PASSIVE_LEVEL)
WDFAPI
NTSTATUS
(NTAPI *PFN_NETMEMORYCREATE)(
    _In_
    PNET_DRIVER_GLOBALS DriverGlobals,
    _In_
    NETMEMORYCOLLECTION MemoryCollection,
    _In_
    CONST NET_MEMORY_CONFIG* Configuration,
    _Out_
    NET_MEMORY_ID* MemoryId
    );

_IRQL_requires_(PASSIVE_LEVEL)
FORCEINLINE
NTSTATUS
NetMemoryCreate(
    _In_
    NETMEMORYCOLLECTION MemoryCollection,
    _In_
    CONST NET_MEMORY_CONFIG* Configuration,
    _Out_
    NET_MEMORY_ID* MemoryId
    )
{
    return ((PFN_NETMEMORYCREATE) NetFunctions[NetMemoryCreateTableIndex])(NetDriverGlobals, MemoryCollection, Configuration, MemoryId);
}

typedef
_IRQL_requires_(PASSIVE_LEVEL)
WDFAPI
void
(NTAPI *PFN_NETMEMORYDESTROY)(
    _In_
    PNET_DRIVER_GLOBALS DriverGlobals,
    _In_
    NETMEMORYCOLLECTION MemoryCollection,
    _In_
    NET_MEMORY_ID MemoryId
    );

_IRQL_requires_(PASSIVE_LEVEL)
FORCEINLINE
void
NetMemoryDestroy(
    _In_
    NETMEMORYCOLLECTION MemoryCollection,
    _In_
    NET_MEMORY_ID MemoryId
    )
{
    ((PFN_NETMEMORYDESTROY) NetFunctions[NetMemoryDestroyTableIndex])(NetDriverGlobals, MemoryCollection, MemoryId);
}

WDF_EXTERN_C_END

#endif
