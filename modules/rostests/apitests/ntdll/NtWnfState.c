/*
 * PROJECT:     OpenNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test the WNF state name and state data system calls
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#include <apitest.h>
#include <ndk/rtlfuncs.h>

#define WNF_TEMPORARY_STATE_NAME    3
#define WNF_DATA_SCOPE_MACHINE      4
#define WNF_INFO_STATE_NAME_EXIST   0
#define WNF_INFO_SUBSCRIBERS        1
#define WNF_WRITERS                 4
#define WNF_WRITES_PER_THREAD       64

typedef struct _TEST_WNF_STATE_NAME
{
    ULONG Data[2];
} TEST_WNF_STATE_NAME;

typedef NTSTATUS (NTAPI *PNT_CREATE_WNF_STATE_NAME)(TEST_WNF_STATE_NAME *, ULONG, ULONG, BOOLEAN, PVOID, ULONG, PSECURITY_DESCRIPTOR);
typedef NTSTATUS (NTAPI *PNT_DELETE_WNF_STATE_NAME)(const TEST_WNF_STATE_NAME *);
typedef NTSTATUS (NTAPI *PNT_UPDATE_WNF_STATE_DATA)(const TEST_WNF_STATE_NAME *, const VOID *, ULONG, PVOID, const VOID *, ULONG, LOGICAL);
typedef NTSTATUS (NTAPI *PNT_QUERY_WNF_STATE_DATA)(const TEST_WNF_STATE_NAME *, PVOID, const VOID *, PULONG, PVOID, PULONG);
typedef NTSTATUS (NTAPI *PNT_QUERY_WNF_STATE_NAME_INFORMATION)(const TEST_WNF_STATE_NAME *, ULONG, const VOID *, PVOID, ULONG);
typedef NTSTATUS (NTAPI *PNT_SUBSCRIBE_WNF_STATE_CHANGE)(const TEST_WNF_STATE_NAME *, ULONG, ULONG, PULONG64);
typedef NTSTATUS (NTAPI *PNT_UNSUBSCRIBE_WNF_STATE_CHANGE)(const TEST_WNF_STATE_NAME *);

static PNT_CREATE_WNF_STATE_NAME pNtCreateWnfStateName;
static PNT_DELETE_WNF_STATE_NAME pNtDeleteWnfStateName;
static PNT_UPDATE_WNF_STATE_DATA pNtUpdateWnfStateData;
static PNT_QUERY_WNF_STATE_DATA pNtQueryWnfStateData;
static PNT_QUERY_WNF_STATE_NAME_INFORMATION pNtQueryWnfStateNameInformation;
static PNT_SUBSCRIBE_WNF_STATE_CHANGE pNtSubscribeWnfStateChange;
static PNT_UNSUBSCRIBE_WNF_STATE_CHANGE pNtUnsubscribeWnfStateChange;

static UCHAR SecurityDescriptorBuffer[SECURITY_DESCRIPTOR_MIN_LENGTH];
static UCHAR AclBuffer[256];

static PSECURITY_DESCRIPTOR
BuildSecurityDescriptor(VOID)
{
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
    UCHAR SidBuffer[SECURITY_MAX_SID_SIZE];
    PSID Everyone = (PSID)SidBuffer;
    PACL Acl = (PACL)AclBuffer;
    PSECURITY_DESCRIPTOR SecurityDescriptor = (PSECURITY_DESCRIPTOR)SecurityDescriptorBuffer;

    RtlInitializeSid(Everyone, &WorldAuthority, 1);
    *RtlSubAuthoritySid(Everyone, 0) = SECURITY_WORLD_RID;
    RtlCreateAcl(Acl, sizeof(AclBuffer), ACL_REVISION);
    RtlAddAccessAllowedAce(Acl, ACL_REVISION, GENERIC_ALL, Everyone);
    RtlCreateSecurityDescriptor(SecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    RtlSetDaclSecurityDescriptor(SecurityDescriptor, TRUE, Acl, FALSE);
    return SecurityDescriptor;
}

static ULONG
QueryNameInformation(_In_ const TEST_WNF_STATE_NAME *StateName, _In_ ULONG InfoClass, _Out_ NTSTATUS *Status)
{
    ULONG Value = 0xCCCCCCCC;

    *Status = pNtQueryWnfStateNameInformation(StateName, InfoClass, NULL, &Value, sizeof(Value));
    return Value;
}

static DWORD WINAPI
WriterThread(_In_ PVOID Parameter)
{
    TEST_WNF_STATE_NAME *StateName = Parameter;
    ULONG Index;
    ULONG Value;

    for (Index = 0; Index < WNF_WRITES_PER_THREAD; Index++)
    {
        Value = GetCurrentThreadId() ^ Index;
        if (!NT_SUCCESS(pNtUpdateWnfStateData(StateName, &Value, sizeof(Value), NULL, NULL, 0, FALSE)))
            return 1;
    }

    return 0;
}

static VOID
TestConcurrentUpdates(_In_ const TEST_WNF_STATE_NAME *StateName, _In_ ULONG StartStamp)
{
    HANDLE Threads[WNF_WRITERS];
    ULONG Stamp = 0, Size, Value;
    DWORD ExitCode;
    NTSTATUS Status;
    ULONG Index;

    for (Index = 0; Index < WNF_WRITERS; Index++)
    {
        Threads[Index] = CreateThread(NULL, 0, WriterThread, (PVOID)StateName, 0, NULL);
        ok(Threads[Index] != NULL, "CreateThread failed with %lu\n", GetLastError());
        if (Threads[Index] == NULL)
            return;
    }

    ok(WaitForMultipleObjects(WNF_WRITERS, Threads, TRUE, 30000) == WAIT_OBJECT_0, "Writers did not finish\n");
    for (Index = 0; Index < WNF_WRITERS; Index++)
    {
        ok(GetExitCodeThread(Threads[Index], &ExitCode) && (ExitCode == 0), "Writer %lu failed\n", Index);
        CloseHandle(Threads[Index]);
    }

    Size = sizeof(Value);
    Status = pNtQueryWnfStateData(StateName, NULL, NULL, &Stamp, &Value, &Size);
    ok(Status == STATUS_SUCCESS, "NtQueryWnfStateData returned 0x%08lx\n", Status);
    ok(Stamp == StartStamp + WNF_WRITERS * WNF_WRITES_PER_THREAD,
       "Concurrent updates lost changes: stamp %lu, expected %lu\n",
       Stamp, StartStamp + WNF_WRITERS * WNF_WRITES_PER_THREAD);
    ok(Size == sizeof(Value), "Size %lu\n", Size);
}

START_TEST(NtWnfState)
{
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
    TEST_WNF_STATE_NAME StateName = {{0, 0}};
    UCHAR Buffer[16];
    ULONG Data = 0x12345678;
    ULONG Stamp, Size, Value;
    ULONG64 SubscriptionId = 0;
    NTSTATUS Status;

    pNtCreateWnfStateName = (PNT_CREATE_WNF_STATE_NAME)GetProcAddress(Ntdll, "NtCreateWnfStateName");
    pNtDeleteWnfStateName = (PNT_DELETE_WNF_STATE_NAME)GetProcAddress(Ntdll, "NtDeleteWnfStateName");
    pNtUpdateWnfStateData = (PNT_UPDATE_WNF_STATE_DATA)GetProcAddress(Ntdll, "NtUpdateWnfStateData");
    pNtQueryWnfStateData = (PNT_QUERY_WNF_STATE_DATA)GetProcAddress(Ntdll, "NtQueryWnfStateData");
    pNtQueryWnfStateNameInformation = (PNT_QUERY_WNF_STATE_NAME_INFORMATION)GetProcAddress(Ntdll, "NtQueryWnfStateNameInformation");
    pNtSubscribeWnfStateChange = (PNT_SUBSCRIBE_WNF_STATE_CHANGE)GetProcAddress(Ntdll, "NtSubscribeWnfStateChange");
    pNtUnsubscribeWnfStateChange = (PNT_UNSUBSCRIBE_WNF_STATE_CHANGE)GetProcAddress(Ntdll, "NtUnsubscribeWnfStateChange");
    if (!pNtCreateWnfStateName || !pNtDeleteWnfStateName || !pNtUpdateWnfStateData || !pNtQueryWnfStateData ||
        !pNtQueryWnfStateNameInformation || !pNtSubscribeWnfStateChange || !pNtUnsubscribeWnfStateChange)
    {
        skip("WNF system calls are not exported\n");
        return;
    }

    Status = pNtCreateWnfStateName(&StateName, WNF_TEMPORARY_STATE_NAME, WNF_DATA_SCOPE_MACHINE, FALSE, NULL,
                                   sizeof(Buffer), BuildSecurityDescriptor());
    ok(Status == STATUS_SUCCESS, "NtCreateWnfStateName returned 0x%08lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;

    Value = QueryNameInformation(&StateName, WNF_INFO_STATE_NAME_EXIST, &Status);
    ok(Status == STATUS_SUCCESS && Value == 1, "Name exists query: 0x%08lx, %lu\n", Status, Value);

    Stamp = 0xCCCCCCCC;
    Size = sizeof(Buffer);
    Status = pNtQueryWnfStateData(&StateName, NULL, NULL, &Stamp, Buffer, &Size);
    ok(Status == STATUS_SUCCESS, "Query of a new name returned 0x%08lx\n", Status);
    ok(Stamp == 0, "New name stamp %lu\n", Stamp);
    ok(Size == 0, "New name size %lu\n", Size);

    Status = pNtUpdateWnfStateData(&StateName, &Data, sizeof(Data), NULL, NULL, 0, FALSE);
    ok(Status == STATUS_SUCCESS, "NtUpdateWnfStateData returned 0x%08lx\n", Status);

    Size = sizeof(Buffer);
    Status = pNtQueryWnfStateData(&StateName, NULL, NULL, &Stamp, Buffer, &Size);
    ok(Status == STATUS_SUCCESS, "NtQueryWnfStateData returned 0x%08lx\n", Status);
    ok(Stamp == 1, "Stamp after one update %lu\n", Stamp);
    ok(Size == sizeof(Data) && *(PULONG)Buffer == Data, "Data size %lu value 0x%08lx\n", Size, *(PULONG)Buffer);

    Status = pNtUpdateWnfStateData(&StateName, &Data, sizeof(Data), NULL, NULL, 5, TRUE);
    ok(!NT_SUCCESS(Status), "An update with a stale stamp returned 0x%08lx\n", Status);

    Size = 1;
    Status = pNtQueryWnfStateData(&StateName, NULL, NULL, &Stamp, Buffer, &Size);
    ok(Status == STATUS_BUFFER_TOO_SMALL, "Small buffer query returned 0x%08lx\n", Status);
    ok(Size == sizeof(Data), "Required size %lu\n", Size);

    Status = pNtSubscribeWnfStateChange(&StateName, 0, 1, &SubscriptionId);
    ok(Status == STATUS_SUCCESS, "NtSubscribeWnfStateChange returned 0x%08lx\n", Status);
    Value = QueryNameInformation(&StateName, WNF_INFO_SUBSCRIBERS, &Status);
    ok(Status == STATUS_SUCCESS && Value == 1, "Subscribers present: 0x%08lx, %lu\n", Status, Value);
    Status = pNtUnsubscribeWnfStateChange(&StateName);
    ok(Status == STATUS_SUCCESS, "NtUnsubscribeWnfStateChange returned 0x%08lx\n", Status);
    Value = QueryNameInformation(&StateName, WNF_INFO_SUBSCRIBERS, &Status);
    ok(Status == STATUS_SUCCESS && Value == 0, "Subscribers after unsubscribe: 0x%08lx, %lu\n", Status, Value);

    TestConcurrentUpdates(&StateName, 1);

    Status = pNtDeleteWnfStateName(&StateName);
    ok(Status == STATUS_SUCCESS, "NtDeleteWnfStateName returned 0x%08lx\n", Status);
    Value = QueryNameInformation(&StateName, WNF_INFO_STATE_NAME_EXIST, &Status);
    ok(Status == STATUS_SUCCESS && Value == 0, "Deleted name exists query: 0x%08lx, %lu\n", Status, Value);
    Size = sizeof(Buffer);
    Status = pNtQueryWnfStateData(&StateName, NULL, NULL, &Stamp, Buffer, &Size);
    ok(Status == STATUS_OBJECT_NAME_NOT_FOUND, "Query of a deleted name returned 0x%08lx\n", Status);
    Status = pNtDeleteWnfStateName(&StateName);
    ok(Status == STATUS_OBJECT_NAME_NOT_FOUND, "Second delete returned 0x%08lx\n", Status);
}
