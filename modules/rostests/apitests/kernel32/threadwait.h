/*
 * PROJECT:     OpenNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Wait until a test thread is blocked in a wait
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#define ANY_WAIT_REASON MAXULONG

static ULONG LastThreadState = MAXULONG;
static ULONG LastWaitReason = MAXULONG;

static BOOL
FindThreadWaitState(
    _In_ PSYSTEM_PROCESS_INFORMATION Process,
    _In_ DWORD ThreadId,
    _In_ ULONG WaitReason)
{
    PSYSTEM_THREAD_INFORMATION Thread;
    ULONG Index;

    for (;;)
    {
        if (Process->UniqueProcessId == UlongToHandle(GetCurrentProcessId()))
            break;
        if (Process->NextEntryOffset == 0)
            return FALSE;
        Process = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Process + Process->NextEntryOffset);
    }

    Thread = (PSYSTEM_THREAD_INFORMATION)(Process + 1);
    for (Index = 0; Index < Process->NumberOfThreads; Index++)
    {
        if (Thread[Index].ClientId.UniqueThread != UlongToHandle(ThreadId))
            continue;

        LastThreadState = Thread[Index].ThreadState;
        LastWaitReason = Thread[Index].WaitReason;
        return (Thread[Index].ThreadState == Waiting) &&
               ((WaitReason == ANY_WAIT_REASON) || (Thread[Index].WaitReason == WaitReason));
    }

    return FALSE;
}

static BOOL
WaitForThreadWaitState(
    _In_ DWORD ThreadId,
    _In_opt_ volatile LONG *Started,
    _In_ ULONG WaitReason,
    _In_ DWORD Timeout)
{
    ULONG Size = 0x40000;
    PVOID Buffer = NULL;
    DWORD Start = GetTickCount();
    BOOL Found = FALSE;
    NTSTATUS Status;

    LastThreadState = MAXULONG;
    LastWaitReason = MAXULONG;
    while (!Found && ((GetTickCount() - Start) < Timeout))
    {
        if (Buffer == NULL)
        {
            Buffer = HeapAlloc(GetProcessHeap(), 0, Size);
            if (Buffer == NULL)
                return FALSE;
        }

        if ((Started == NULL) || (InterlockedCompareExchange(Started, 0, 0) != 0))
        {
            Status = NtQuerySystemInformation(SystemProcessInformation, Buffer, Size, NULL);
            if (Status == STATUS_INFO_LENGTH_MISMATCH)
            {
                HeapFree(GetProcessHeap(), 0, Buffer);
                Buffer = NULL;
                Size *= 2;
                continue;
            }
            if (!NT_SUCCESS(Status))
                break;

            Found = FindThreadWaitState(Buffer, ThreadId, WaitReason);
        }

        if (!Found)
            Sleep(1);
    }

    if (Buffer != NULL)
        HeapFree(GetProcessHeap(), 0, Buffer);

    return Found;
}
