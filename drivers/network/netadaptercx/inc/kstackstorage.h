/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Fixed-capacity stack of free items
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#include <kmacros.h>
#include <karray.h>

template <typename T>
class KStackPool
{
public:

    KStackPool(
        void) = default;

    PAGED
    bool
    resize(
        _In_ size_t Count)
    {
        return m_Stack.resize(Count);
    }

    NONPAGED
    void
    PushToReturn(
        _In_ T Item)
    {
        NT_FRE_ASSERT(!IsFull());
        m_Stack[m_CurrentIndex++] = Item;
    }

    NONPAGED
    T
    PopToUse(
        void)
    {
        NT_FRE_ASSERT(!IsEmpty());
        return m_Stack[--m_CurrentIndex];
    }

    NONPAGED
    T &
    operator[](
        _In_ size_t Index)
    {
        return m_Stack[Index];
    }

    NONPAGED
    bool
    IsEmpty(
        void) const
    {
        return m_CurrentIndex == 0;
    }

    NONPAGED
    bool
    IsFull(
        void) const
    {
        return m_CurrentIndex == m_Stack.count();
    }

    NONPAGED
    size_t
    Size(
        void) const
    {
        return m_CurrentIndex;
    }

private:

    Rtl::KArray<T, NonPagedPoolNx>
        m_Stack;

    size_t
        m_CurrentIndex = 0;
};
