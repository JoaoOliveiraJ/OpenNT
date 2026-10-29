/*
 * PROJECT:     OpenNT Named Pipe FileSystem
 * LICENSE:     BSD - See COPYING.ARM in the top level directory
 * PURPOSE:     Named pipe directory enumeration
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif.ing@outlook.com>
 */

#include "npfs.h"

static
ULONG
NpDirectoryNameOffset(IN FILE_INFORMATION_CLASS InformationClass)
{
    switch (InformationClass)
    {
        case FileDirectoryInformation:
            return FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName);
        case FileFullDirectoryInformation:
            return FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName);
        case FileIdFullDirectoryInformation:
            return FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName);
        case FileBothDirectoryInformation:
            return FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName);
        case FileIdBothDirectoryInformation:
            return FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName);
        case FileNamesInformation:
            return FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName);
        default:
            return 0;
    }
}

static
VOID
NpFillDirectoryEntry(IN FILE_INFORMATION_CLASS InformationClass,
                     IN PUCHAR Entry,
                     IN ULONG NameOffset,
                     IN ULONG FileIndex,
                     IN PNP_FCB Fcb,
                     IN ULONG NameLength)
{
    RtlZeroMemory(Entry, NameOffset);

    if (InformationClass == FileNamesInformation)
    {
        PFILE_NAMES_INFORMATION Names = (PFILE_NAMES_INFORMATION)Entry;

        Names->FileIndex = FileIndex;
        Names->FileNameLength = Fcb->ShortName.Length;
    }
    else
    {
        PFILE_DIRECTORY_INFORMATION Directory = (PFILE_DIRECTORY_INFORMATION)Entry;

        Directory->FileIndex = FileIndex;
        Directory->EndOfFile.QuadPart = Fcb->CurrentInstances;
        Directory->AllocationSize.QuadPart = Fcb->MaximumInstances;
        Directory->FileAttributes = FILE_ATTRIBUTE_NORMAL;
        Directory->FileNameLength = Fcb->ShortName.Length;
    }

    RtlCopyMemory(Entry + NameOffset, Fcb->ShortName.Buffer, NameLength);
}

static
NTSTATUS
NpSetQueryTemplate(IN PNP_ROOT_DCB_FCB Ccb,
                   IN PUNICODE_STRING FileName)
{
    static const WCHAR MatchAll = L'*';
    PUNICODE_STRING QueryTemplate;
    USHORT Length;
    NTSTATUS Status;

    Length = (FileName && FileName->Length) ? FileName->Length : sizeof(MatchAll);
    QueryTemplate = ExAllocatePoolWithTag(PagedPool,
                                          sizeof(UNICODE_STRING) + Length,
                                          NPFS_ROOT_DCB_CCB_TAG);
    if (!QueryTemplate) return STATUS_INSUFFICIENT_RESOURCES;

    QueryTemplate->Length = 0;
    QueryTemplate->MaximumLength = Length;
    QueryTemplate->Buffer = (PWCHAR)(QueryTemplate + 1);

    if (FileName && FileName->Length)
    {
        Status = RtlUpcaseUnicodeString(QueryTemplate, FileName, FALSE);
        if (!NT_SUCCESS(Status))
        {
            ExFreePool(QueryTemplate);
            return Status;
        }
    }
    else
    {
        QueryTemplate->Buffer[0] = MatchAll;
        QueryTemplate->Length = sizeof(MatchAll);
    }

    if (Ccb->QueryTemplate) ExFreePool(Ccb->QueryTemplate);
    Ccb->QueryTemplate = QueryTemplate;
    Ccb->IndexOfLastCcbReturned = 0;
    return STATUS_SUCCESS;
}

static
NTSTATUS
NpQueryDirectory(IN PNP_DCB Dcb,
                 IN PNP_ROOT_DCB_FCB Ccb,
                 IN PIRP Irp)
{
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    FILE_INFORMATION_CLASS InformationClass;
    PUNICODE_STRING FileName;
    BOOLEAN InitialQuery, ReturnSingleEntry, Found = FALSE, Overflow = FALSE;
    ULONG Length, NameOffset, Index, NextIndex, Offset = 0, LastOffset = 0, UsedLength = 0;
    ULONG EntryLength, NameLength;
    PLIST_ENTRY NextEntry;
    PUCHAR Buffer;
    PNP_FCB Fcb;
    NTSTATUS Status;
    PAGED_CODE();

    InformationClass = IoStack->Parameters.QueryDirectory.FileInformationClass;
    Length = IoStack->Parameters.QueryDirectory.Length;
    FileName = IoStack->Parameters.QueryDirectory.FileName;
    ReturnSingleEntry = BooleanFlagOn(IoStack->Flags, SL_RETURN_SINGLE_ENTRY);

    NameOffset = NpDirectoryNameOffset(InformationClass);
    if (!NameOffset) return STATUS_INVALID_INFO_CLASS;
    if (Length < NameOffset) return STATUS_INFO_LENGTH_MISMATCH;

    InitialQuery = !Ccb->QueryTemplate;
    if (InitialQuery || (BooleanFlagOn(IoStack->Flags, SL_RESTART_SCAN) && FileName && FileName->Length))
    {
        Status = NpSetQueryTemplate(Ccb, FileName);
        if (!NT_SUCCESS(Status)) return Status;
        InitialQuery = TRUE;
    }
    else if (BooleanFlagOn(IoStack->Flags, SL_RESTART_SCAN))
    {
        Ccb->IndexOfLastCcbReturned = 0;
        InitialQuery = TRUE;
    }

    if (BooleanFlagOn(IoStack->Flags, SL_INDEX_SPECIFIED))
        Ccb->IndexOfLastCcbReturned = IoStack->Parameters.QueryDirectory.FileIndex;

    if (Irp->MdlAddress)
    {
        Buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
        if (!Buffer) return STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
        Buffer = Irp->UserBuffer;
    }

    NextIndex = Ccb->IndexOfLastCcbReturned;
    Status = STATUS_SUCCESS;

    _SEH2_TRY
    {
        Index = 0;
        for (NextEntry = Dcb->FcbList.Flink;
             NextEntry != &Dcb->FcbList;
             NextEntry = NextEntry->Flink, Index++)
        {
            if (Index < Ccb->IndexOfLastCcbReturned) continue;

            Fcb = CONTAINING_RECORD(NextEntry, NP_FCB, DcbEntry);
            if (!FsRtlIsNameInExpression(Ccb->QueryTemplate, &Fcb->ShortName, TRUE, NULL))
            {
                NextIndex = Index + 1;
                continue;
            }

            if (Found) Offset = ALIGN_UP_BY(UsedLength, sizeof(LONGLONG));
            NameLength = Fcb->ShortName.Length;
            EntryLength = NameOffset + NameLength;

            if (Offset + EntryLength > Length)
            {
                if (!Found)
                {
                    NpFillDirectoryEntry(InformationClass, Buffer, NameOffset, Index,
                                         Fcb, Length - NameOffset);
                    UsedLength = Length;
                    Overflow = TRUE;
                }
                break;
            }

            NpFillDirectoryEntry(InformationClass, Buffer + Offset, NameOffset, Index,
                                 Fcb, NameLength);
            if (Found) *(PULONG)(Buffer + LastOffset) = Offset - LastOffset;

            Found = TRUE;
            LastOffset = Offset;
            UsedLength = Offset + EntryLength;
            NextIndex = Index + 1;

            if (ReturnSingleEntry) break;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    if (!NT_SUCCESS(Status)) return Status;

    if (Overflow)
    {
        Irp->IoStatus.Information = UsedLength;
        return STATUS_BUFFER_OVERFLOW;
    }

    Ccb->IndexOfLastCcbReturned = NextIndex;
    if (!Found) return InitialQuery ? STATUS_NO_SUCH_FILE : STATUS_NO_MORE_FILES;

    Irp->IoStatus.Information = UsedLength;
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
NpFsdDirectoryControl(IN PDEVICE_OBJECT DeviceObject,
                      IN PIRP Irp)
{
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    PNP_ROOT_DCB_FCB Ccb;
    PNP_DCB Dcb;
    NTSTATUS Status;
    PAGED_CODE();
    TRACE("Entered\n");

    Irp->IoStatus.Information = 0;

    if (IoStack->MinorFunction != IRP_MN_QUERY_DIRECTORY)
    {
        UNIMPLEMENTED;
        Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_NOT_IMPLEMENTED;
    }

    FsRtlEnterFileSystem();
    NpAcquireSharedVcb();

    if (NpDecodeFileObject(IoStack->FileObject, (PVOID *)&Dcb, (PNP_CCB *)&Ccb, NULL) != NPFS_NTC_ROOT_DCB)
        Status = STATUS_INVALID_PARAMETER;
    else
        Status = NpQueryDirectory(Dcb, Ccb, Irp);

    NpReleaseVcb();
    FsRtlExitFileSystem();

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NAMED_PIPE_INCREMENT);

    TRACE("Leaving, Status = %lx\n", Status);
    return Status;
}

/* EOF */
