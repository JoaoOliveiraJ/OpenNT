/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     TraceLogging provider macros used by the NetAdapterCx sources
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

/* TODO: emit TraceLogging events once OpenNT has an ETW TraceLogging provider; until then a
 * registered provider behaves as one with no listener. */

typedef struct _NETCX_TRACELOGGING_PROVIDER
{
    GUID ProviderId;
} NETCX_TRACELOGGING_PROVIDER;

typedef NETCX_TRACELOGGING_PROVIDER const * TraceLoggingHProvider;

#define TRACELOGGING_DECLARE_PROVIDER(_Handle) \
    extern TraceLoggingHProvider const _Handle

#define NETCX_TRACELOGGING_GUID(_L, _W1, _W2, _B0, _B1, _B2, _B3, _B4, _B5, _B6, _B7) \
    { _L, _W1, _W2, { _B0, _B1, _B2, _B3, _B4, _B5, _B6, _B7 } }

#define TRACELOGGING_DEFINE_PROVIDER(_Handle, _Name, _Guid, ...) \
    static NETCX_TRACELOGGING_PROVIDER const _Handle##_Storage = { NETCX_TRACELOGGING_GUID _Guid }; \
    TraceLoggingHProvider const _Handle = &_Handle##_Storage

#define TraceLoggingRegister(_Handle) (UNREFERENCED_PARAMETER(_Handle), STATUS_SUCCESS)
#define TraceLoggingUnregister(_Handle) ((void)(_Handle))
#define TraceLoggingWrite(_Handle, _Name, ...) ((void)(_Handle))

#define TraceLoggingDescription(...)
#define TraceLoggingKeyword(...)
#define TraceLoggingHexInt32(...)
#define TraceLoggingUInt32(...)
#define TraceLoggingHexUInt64(...)
#define TraceLoggingGuid(...)
