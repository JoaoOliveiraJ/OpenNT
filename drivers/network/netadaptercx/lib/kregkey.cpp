/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Registry key helpers NetAdapterCx uses
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#include <ntosp.h>
#include <knew.h>
#include <kregkey.h>

PAGED
NTSTATUS
KRegKey::Open(
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCWSTR Name,
    _In_opt_ HANDLE ParentKey)
{
    UNICODE_STRING name;
    NTSTATUS status = RtlUnicodeStringInit(&name, Name);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    return Open(DesiredAccess, &name, ParentKey);
}

PAGED
NTSTATUS
KRegKey::Open(
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCUNICODE_STRING Name,
    _In_opt_ HANDLE ParentKey)
{
    OBJECT_ATTRIBUTES attributes;
    HANDLE key;

    InitializeObjectAttributes(
        &attributes,
        const_cast<PUNICODE_STRING>(Name),
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        ParentKey,
        nullptr);

    NTSTATUS status = ZwOpenKey(&key, DesiredAccess, &attributes);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    reset(key);
    return STATUS_SUCCESS;
}

PAGED
NTSTATUS
KRegKey::QueryValueUlong(
    _In_ PCWSTR Name,
    _Out_ ULONG * Value)
{
    UNICODE_STRING name;
    NTSTATUS status = RtlUnicodeStringInit(&name, Name);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    return QueryValueUlong(&name, Value);
}

PAGED
NTSTATUS
KRegKey::QueryValueUlong(
    _In_ PCUNICODE_STRING Name,
    _Out_ ULONG * Value)
{
    *Value = 0;

    return QueryValueBlob(
        Name,
        [Value](UCHAR const * Data, ULONG DataLength)
        {
            if (DataLength != sizeof(ULONG))
            {
                return STATUS_OBJECT_TYPE_MISMATCH;
            }

            RtlCopyMemory(Value, Data, sizeof(ULONG));
            return STATUS_SUCCESS;
        },
        REG_DWORD);
}
