/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Trace and return macros of nxtrace.hpp without the WPP preprocessor
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#define NETCX_TRACE_ERROR(_Flags) \
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "NetAdapterCx: %s(%d)\n", __FUNCTION__, __LINE__)

#define NETCX_TRACE_STATUS(_Status) \
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "NetAdapterCx: %s(%d) failed 0x%08lx\n", __FUNCTION__, __LINE__, (ULONG)(_Status))

#define LogVerbose(_Flags, ...) ((void)0)
#define LogInfo(_Flags, ...) ((void)0)
#define LogWarning(_Flags, ...) ((void)0)
#define LogError(_Flags, ...) NETCX_TRACE_ERROR(_Flags)

#define CX_RETURN_MSG(...) \
    do { return; } while (0)

#define CX_RETURN_STATUS_SUCCESS_MSG(...) \
    do { return STATUS_SUCCESS; } while (0)

#define CX_RETURN_IF_NOT_NT_SUCCESS_MSG(_Expression, ...) \
    do { NTSTATUS nt__wpp = (_Expression); if (!NT_SUCCESS(nt__wpp)) { NETCX_TRACE_STATUS(nt__wpp); return nt__wpp; } } while (0)

#define CX_LOG_IF_NOT_NT_SUCCESS_MSG(_Expression, ...) \
    [&]() { NTSTATUS nt__wpp = (_Expression); if (!NT_SUCCESS(nt__wpp)) { NETCX_TRACE_STATUS(nt__wpp); } return nt__wpp; }()

#define CX_RETURN_IF_NOT_NT_SUCCESS(_Expression) \
    do { NTSTATUS nt__wpp = (_Expression); if (!NT_SUCCESS(nt__wpp)) { NETCX_TRACE_STATUS(nt__wpp); return nt__wpp; } } while (0)

#define CX_RETURN_NDIS_STATUS_IF_NOT_STATUS_SUCCESS(_Expression) \
    do { NTSTATUS nt__wpp = (_Expression); if (STATUS_SUCCESS != nt__wpp) { NETCX_TRACE_STATUS(nt__wpp); return NdisConvertNtStatusToNdisStatus(nt__wpp); } } while (0)

#define CX_RETURN_NTSTATUS_IF_NOT_NDIS_STATUS_SUCCESS(_Expression) \
    do { NDIS_STATUS ndis__wpp = (_Expression); if (NDIS_STATUS_SUCCESS != ndis__wpp) { NETCX_TRACE_STATUS(ndis__wpp); return NdisConvertNdisStatusToNtStatus(ndis__wpp); } } while (0)

#define CX_RETURN_NTSTATUS_IF(_Status, _Condition) \
    do { if ((_Condition)) { NETCX_TRACE_STATUS(_Status); return (_Status); } } while (0)

#define CX_RETURN_NTSTATUS_IF_MSG(_Status, _Condition, ...) \
    do { if ((_Condition)) { NETCX_TRACE_STATUS(_Status); return (_Status); } } while (0)

#define CX_WARNING_RETURN_NTSTATUS_IF_MSG(_Status, _Condition, ...) \
    do { if ((_Condition)) { return (_Status); } } while (0)

#define CX_RETURN_NULL_IF_NOT_NT_SUCCESS(_Expression) \
    do { NTSTATUS nt__wpp = (_Expression); if (!NT_SUCCESS(nt__wpp)) { NETCX_TRACE_STATUS(nt__wpp); return nullptr; } } while (0)

#define CX_RETURN_NULL_IF_NOT_NT_SUCCESS_MSG(_Expression, ...) \
    do { NTSTATUS nt__wpp = (_Expression); if (!NT_SUCCESS(nt__wpp)) { NETCX_TRACE_STATUS(nt__wpp); return nullptr; } } while (0)

#define CX_RETURN_VOID_IF_NOT_NT_SUCCESS_MSG(_Expression, ...) \
    do { NTSTATUS nt__wpp = (_Expression); if (!NT_SUCCESS(nt__wpp)) { NETCX_TRACE_STATUS(nt__wpp); return; } } while (0)

#define CX_RETURN_IF_NULL(_Pointer, ...) \
    do { if ((_Pointer) == nullptr) { return STATUS_INVALID_PARAMETER; } } while (0)

#ifndef WPP_INIT_TRACING
#define WPP_INIT_TRACING(_DriverObject, _RegistryPath) ((void)(_DriverObject), (void)(_RegistryPath))
#endif

#ifndef WPP_CLEANUP
#define WPP_CLEANUP(_DriverObject) ((void)(_DriverObject))
#endif
