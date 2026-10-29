/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Ordered and unordered reads and writes of shared integers
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

namespace mem
{

template <typename T>
inline
T
ReadAcquire(
    _In_ T const volatile * Source)
{
    static_assert(sizeof(T) == sizeof(LONG) || sizeof(T) == sizeof(LONG64), "unsupported width");

    if constexpr (sizeof(T) == sizeof(LONG))
    {
        return static_cast<T>(::ReadAcquire(reinterpret_cast<LONG const volatile *>(Source)));
    }
    else
    {
        return static_cast<T>(::ReadAcquire64(reinterpret_cast<LONG64 const volatile *>(Source)));
    }
}

template <typename T>
inline
T
ReadNoFence(
    _In_ T const volatile * Source)
{
    static_assert(sizeof(T) == sizeof(LONG) || sizeof(T) == sizeof(LONG64), "unsupported width");

    if constexpr (sizeof(T) == sizeof(LONG))
    {
        return static_cast<T>(::ReadNoFence(reinterpret_cast<LONG const volatile *>(Source)));
    }
    else
    {
        return static_cast<T>(::ReadNoFence64(reinterpret_cast<LONG64 const volatile *>(Source)));
    }
}

template <typename T, typename V>
inline
void
WriteRelease(
    _Out_ T volatile * Destination,
    _In_ V Value)
{
    static_assert(sizeof(T) == sizeof(LONG) || sizeof(T) == sizeof(LONG64), "unsupported width");

    if constexpr (sizeof(T) == sizeof(LONG))
    {
        ::WriteRelease(reinterpret_cast<LONG volatile *>(Destination), static_cast<LONG>(Value));
    }
    else
    {
        ::WriteRelease64(reinterpret_cast<LONG64 volatile *>(Destination), static_cast<LONG64>(Value));
    }
}

}
