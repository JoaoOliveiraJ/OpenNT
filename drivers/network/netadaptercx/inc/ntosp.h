/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Kernel declarations the NetAdapterCx sources take from ntosp.h
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#include <ntifs.h>
#include <ntintsafe.h>
#include <ntassert.h>
#include <devpkey.h>
#include <nt/rtl/integermacro.h>

typedef struct _RTL_BITMAP_EX
{
    ULONG64 SizeOfBitMap;
    PULONG64 Buffer;
} RTL_BITMAP_EX, *PRTL_BITMAP_EX;

C_ASSERT(sizeof(RTL_BITMAP_EX) == 16);

EXTERN_C
NTSYSAPI
VOID
NTAPI
RtlInitializeBitMapEx(
    _Out_ PRTL_BITMAP_EX BitMapHeader,
    _In_opt_ PULONG64 BitMapBuffer,
    _In_ ULONG64 SizeOfBitMap);

EXTERN_C
NTSYSAPI
VOID
NTAPI
RtlClearAllBitsEx(
    _In_ PRTL_BITMAP_EX BitMapHeader);

EXTERN_C
NTSYSAPI
VOID
NTAPI
RtlClearBitEx(
    _In_ PRTL_BITMAP_EX BitMapHeader,
    _In_ ULONG64 BitNumber);

EXTERN_C
NTSYSAPI
VOID
NTAPI
RtlSetBitEx(
    _In_ PRTL_BITMAP_EX BitMapHeader,
    _In_ ULONG64 BitNumber);

EXTERN_C
NTSYSAPI
BOOLEAN
NTAPI
RtlTestBitEx(
    _In_ PRTL_BITMAP_EX BitMapHeader,
    _In_ ULONG64 BitNumber);

EXTERN_C
NTSYSAPI
ULONG64
NTAPI
RtlFindSetBitsEx(
    _In_ PRTL_BITMAP_EX BitMapHeader,
    _In_ ULONG64 NumberToFind,
    _In_ ULONG64 HintIndex);

EXTERN_C
NTSYSAPI
ULONG64
NTAPI
RtlFindSetBitsAndClearEx(
    _In_ PRTL_BITMAP_EX BitMapHeader,
    _In_ ULONG64 NumberToFind,
    _In_ ULONG64 HintIndex);

#define RtlCheckBitEx(BitMapHeader, BitNumber) RtlTestBitEx((BitMapHeader), (BitNumber))

#ifndef BUGCODE_NETADAPTER_DRIVER
#define BUGCODE_NETADAPTER_DRIVER ((ULONG)0x0000019EL)
#endif

#define NETADAPTERCX_BUGCHECK_DEVICE_RESET 0x54

typedef union _DBGK_LIVEDUMP_FLAGS
{
    struct
    {
        ULONG UserPages : 1;
        ULONG RequestMinidump : 1;
        ULONG HypervisorPages : 1;
        ULONG NoDeferWrite : 1;
        ULONG Reserved : 28;
    };
    ULONG AsUlong;
} DBGK_LIVEDUMP_FLAGS;

C_ASSERT(sizeof(DBGK_LIVEDUMP_FLAGS) == 4);

typedef
NTSTATUS
(*PDBGK_LIVEDUMP_ADDSECONDARYDATA_ROUTINE)(
    _In_ HANDLE ReportHandle,
    _In_reads_bytes_(sizeof(GUID)) LPCGUID Identifier,
    _In_reads_bytes_(Size) PVOID Data,
    _In_ ULONG Size);

typedef
NTSTATUS
DBGK_LIVEDUMP_CALLBACK_ROUTINE(
    _In_ HANDLE ReportHandle,
    _In_ PDBGK_LIVEDUMP_ADDSECONDARYDATA_ROUTINE AddSecondaryDataRoutine,
    _In_ ULONG BugCheckCode,
    _In_opt_ ULONG_PTR P1,
    _In_opt_ ULONG_PTR P2,
    _In_opt_ ULONG_PTR P3,
    _In_opt_ ULONG_PTR P4,
    _In_opt_ PVOID CallbackContext);

typedef DBGK_LIVEDUMP_CALLBACK_ROUTINE * PDBGK_LIVEDUMP_CALLBACK_ROUTINE;

EXTERN_C
NTKERNELAPI
NTSTATUS
NTAPI
DbgkWerCaptureLiveKernelDump(
    _In_ PCWSTR ComponentName,
    _In_ ULONG BugCheckCode,
    _In_opt_ ULONG_PTR P1,
    _In_opt_ ULONG_PTR P2,
    _In_opt_ ULONG_PTR P3,
    _In_opt_ ULONG_PTR P4,
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PDBGK_LIVEDUMP_CALLBACK_ROUTINE CallbackFunction,
    _In_ DBGK_LIVEDUMP_FLAGS Flags);
