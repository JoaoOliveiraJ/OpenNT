/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Counted string helpers
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#include <kmacros.h>
#include <kptr.h>

namespace Rtl
{

class KString;

PAGED
inline
KPoolPtr<UNICODE_STRING>
DuplicateUnicodeString(
    _In_ UNICODE_STRING const & Source,
    _In_ ULONG PoolTag)
{
    size_t const allocationSize = sizeof(UNICODE_STRING) + Source.Length + sizeof(WCHAR);

    if (allocationSize > sizeof(UNICODE_STRING) + MAXUSHORT)
    {
        return nullptr;
    }

    auto copy = MakeSizedPoolPtr<UNICODE_STRING>(PoolTag, allocationSize);

    if (!copy)
    {
        return nullptr;
    }

    auto buffer = reinterpret_cast<PWCH>(copy.get() + 1);
    RtlCopyMemory(buffer, Source.Buffer, Source.Length);
    buffer[Source.Length / sizeof(WCHAR)] = UNICODE_NULL;

    copy->Buffer = buffer;
    copy->Length = Source.Length;
    copy->MaximumLength = static_cast<USHORT>(Source.Length + sizeof(WCHAR));

    return copy;
}

}
