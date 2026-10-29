/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Events of the Microsoft-Windows-Network-ExecutionContext provider
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

/* TODO: register the Microsoft-Windows-Network-ExecutionContext ETW provider and write its events */

inline
ULONG
EventRegisterMicrosoft_Windows_Network_ExecutionContext(
    void)
{
    return 0;
}

inline
ULONG
EventUnregisterMicrosoft_Windows_Network_ExecutionContext(
    void)
{
    return 0;
}

#define NX_EC_EVENT(Name) \
    template <typename... Arguments> \
    inline ULONG Name(Arguments &&...) { return 0; }

NX_EC_EVENT(EventWriteDispatcherInsertActiveList)
NX_EC_EVENT(EventWriteDispatcherInsertReadyList)
NX_EC_EVENT(EventWriteDispatcherRemoveActiveList)
NX_EC_EVENT(EventWriteDispatcherRemoveReadyList)
NX_EC_EVENT(EventWriteDispatcherStateChange)
NX_EC_EVENT(EventWriteExecutionContextStateChange)
NX_EC_EVENT(EventWriteExecutionTimeExceededWarning)

#undef NX_EC_EVENT
