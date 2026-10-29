/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Global allocation operators of the NetAdapterCx kernel runtime
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#include <ntosp.h>
#include <knew.h>

#define NETCX_DEFAULT_POOL_TAG 'xCdN'

namespace std
{
const nothrow_t nothrow{};
}

extern "C"
void
__cdecl
_purecall(
    void);

extern "C"
void
__cxa_pure_virtual(
    void)
{
    _purecall();
}

static
void *
AllocatePool(
    _In_ size_t Size,
    _In_ ULONG PoolFlags,
    _In_ ULONG Tag)
{
    return ExAllocatePool2(PoolFlags, Size != 0 ? Size : 1, Tag);
}

void *
operator new(
    size_t Size,
    std::nothrow_t const &,
    ULONG Tag)
{
    return AllocatePool(Size, POOL_FLAG_PAGED, Tag);
}

void *
operator new[](
    size_t Size,
    std::nothrow_t const &,
    ULONG Tag)
{
    return AllocatePool(Size, POOL_FLAG_PAGED, Tag);
}

void *
operator new(
    size_t Size,
    std::nothrow_t const &) noexcept
{
    return AllocatePool(Size, POOL_FLAG_NON_PAGED, NETCX_DEFAULT_POOL_TAG);
}

void *
operator new[](
    size_t Size,
    std::nothrow_t const &) noexcept
{
    return AllocatePool(Size, POOL_FLAG_NON_PAGED, NETCX_DEFAULT_POOL_TAG);
}

void
operator delete(
    void * Pointer,
    ULONG Tag)
{
    if (Pointer != nullptr)
    {
        ExFreePoolWithTag(Pointer, Tag);
    }
}

void
operator delete[](
    void * Pointer,
    ULONG Tag)
{
    if (Pointer != nullptr)
    {
        ExFreePoolWithTag(Pointer, Tag);
    }
}

void
__cdecl
operator delete(
    void * Pointer) noexcept
{
    if (Pointer != nullptr)
    {
        ExFreePool(Pointer);
    }
}

void
__cdecl
operator delete[](
    void * Pointer) noexcept
{
    if (Pointer != nullptr)
    {
        ExFreePool(Pointer);
    }
}

void
__cdecl
operator delete(
    void * Pointer,
    size_t) noexcept
{
    if (Pointer != nullptr)
    {
        ExFreePool(Pointer);
    }
}

void
__cdecl
operator delete[](
    void * Pointer,
    size_t) noexcept
{
    if (Pointer != nullptr)
    {
        ExFreePool(Pointer);
    }
}
