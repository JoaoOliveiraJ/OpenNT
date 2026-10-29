/*
 * PROJECT:     OpenNT kernel-mode tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test that CcWaitForCurrentLazyWriterActivity covers pending lazy closes
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#include <kmt_test.h>

#define NDEBUG
#include <debug.h>

typedef struct _TEST_FCB
{
    FSRTL_ADVANCED_FCB_HEADER Header;
    SECTION_OBJECT_POINTERS SectionObjectPointers;
    FAST_MUTEX HeaderMutex;
} TEST_FCB, *PTEST_FCB;

static
BOOLEAN
NTAPI
AcquireForLazyWrite(
    _In_ PVOID Context,
    _In_ BOOLEAN Wait)
{
    return TRUE;
}

static
VOID
NTAPI
ReleaseFromLazyWrite(
    _In_ PVOID Context)
{
}

static
BOOLEAN
NTAPI
AcquireForReadAhead(
    _In_ PVOID Context,
    _In_ BOOLEAN Wait)
{
    return TRUE;
}

static
VOID
NTAPI
ReleaseFromReadAhead(
    _In_ PVOID Context)
{
}

static CACHE_MANAGER_CALLBACKS Callbacks = {
    AcquireForLazyWrite,
    ReleaseFromLazyWrite,
    AcquireForReadAhead,
    ReleaseFromReadAhead,
};

static CC_FILE_SIZES FileSizes = {
    RTL_CONSTANT_LARGE_INTEGER((LONGLONG)0x10000),
    RTL_CONSTANT_LARGE_INTEGER((LONGLONG)0x10000),
    RTL_CONSTANT_LARGE_INTEGER((LONGLONG)0x10000)
};

static
VOID
TestLazyClose(VOID)
{
    PFILE_OBJECT FileObject;
    PTEST_FCB Fcb;
    NTSTATUS Status;

    FileObject = IoCreateStreamFileObject(NULL, KmtDriverObject->DeviceObject);
    if (skip(FileObject != NULL, "IoCreateStreamFileObject failed\n"))
        return;

    Fcb = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Fcb), 'zLmK');
    if (skip(Fcb != NULL, "Out of memory\n"))
    {
        ObDereferenceObject(FileObject);
        return;
    }

    RtlZeroMemory(Fcb, sizeof(*Fcb));
    ExInitializeFastMutex(&Fcb->HeaderMutex);
    FsRtlSetupAdvancedHeader(&Fcb->Header, &Fcb->HeaderMutex);
    Fcb->Header.AllocationSize = FileSizes.AllocationSize;
    Fcb->Header.FileSize = FileSizes.FileSize;
    Fcb->Header.ValidDataLength = FileSizes.ValidDataLength;
    FileObject->FsContext = Fcb;
    FileObject->SectionObjectPointer = &Fcb->SectionObjectPointers;

    KmtStartSeh();
    CcInitializeCacheMap(FileObject, &FileSizes, FALSE, &Callbacks, NULL);
    KmtEndSeh(STATUS_SUCCESS);

    if (!skip(CcIsFileCached(FileObject), "CcInitializeCacheMap failed\n"))
    {
        ok(Fcb->SectionObjectPointers.SharedCacheMap != NULL, "No shared cache map after CcInitializeCacheMap\n");
        CcUninitializeCacheMap(FileObject, NULL, NULL);

        Status = CcWaitForCurrentLazyWriterActivity();
        ok_eq_hex(Status, STATUS_SUCCESS);
        ok(Fcb->SectionObjectPointers.SharedCacheMap == NULL,
           "The lazy close of the last cached open was still pending after the lazy writer wait\n");
        if (Fcb->SectionObjectPointers.SharedCacheMap != NULL)
            return;
    }

    FileObject->SectionObjectPointer = NULL;
    FileObject->FsContext = NULL;
    ExFreePoolWithTag(Fcb, 'zLmK');
    ObDereferenceObject(FileObject);
}

START_TEST(CcLazyWriter)
{
    NTSTATUS Status;

    Status = CcWaitForCurrentLazyWriterActivity();
    ok_eq_hex(Status, STATUS_SUCCESS);

    TestLazyClose();
}
