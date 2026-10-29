/*
 * PROJECT:     OpenNT Boot Loader
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Mark a firmware boot as a test run with the SMBIOS OEM string the harness passes
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif.ing@outlook.com>
 */

#include <blefi.h>
#include <arc/loaderblk.h>

#define SMBIOS_TYPE_OEM_STRINGS     11
#define SMBIOS_TYPE_END             127
#define SMBIOS_OEM_STRINGS_LENGTH   5
#define SMBIOS_MAX_HANDLE           0xFEFF

static const CHAR TestRunString[] = "opennt.applaunch";
static EFI_GUID SmbiosGuid = SMBIOS_TABLE_GUID;
static EFI_GUID Smbios3Guid = SMBIOS3_TABLE_GUID;

typedef struct _TABLE_SCAN
{
    ULONG EndOffset;
    ULONG EndSize;
    ULONG MaxSize;
    USHORT Count;
    USHORT NextHandle;
    BOOLEAN Present;
} TABLE_SCAN, *PTABLE_SCAN;

static EFI_SYSTEM_TABLE* SystemTable;

static VOID
Say(CHAR16* Text)
{
    SystemTable->ConOut->OutputString(SystemTable->ConOut, Text);
}

static PVOID
FindTable(EFI_GUID* Guid)
{
    UINTN i;

    for (i = 0; i < SystemTable->NumberOfTableEntries; i++)
    {
        if (RtlEqualMemory(&SystemTable->ConfigurationTable[i].VendorGuid, Guid, sizeof(EFI_GUID)))
            return SystemTable->ConfigurationTable[i].VendorTable;
    }

    return NULL;
}

static UCHAR
Checksum(const UCHAR* Data, ULONG Length)
{
    UCHAR Sum = 0;

    while (Length--)
        Sum += *Data++;

    return (UCHAR)(0 - Sum);
}

static BOOLEAN
HasTestRunString(const UCHAR* Strings, const UCHAR* End)
{
    while (Strings < End && *Strings)
    {
        if (strcmp((PCSTR)Strings, TestRunString) == 0)
            return TRUE;
        Strings += strlen((PCSTR)Strings) + 1;
    }

    return FALSE;
}

static BOOLEAN
ScanTable(const UCHAR* Table, ULONG Length, PTABLE_SCAN Scan)
{
    ULONG Offset = 0;
    ULONG Handle = 0;
    const SMBIOS_HEADER* Header;
    ULONG Next;

    RtlZeroMemory(Scan, sizeof(*Scan));

    while (Offset + sizeof(SMBIOS_HEADER) <= Length)
    {
        Header = (const SMBIOS_HEADER*)(Table + Offset);
        if (Header->Length < sizeof(SMBIOS_HEADER) || Offset + Header->Length >= Length)
            return FALSE;

        Next = Offset + Header->Length;
        while (Next + 1 < Length && (Table[Next] || Table[Next + 1]))
            Next++;
        if (Next + 1 >= Length)
            return FALSE;
        Next += 2;

        if (Header->Type == SMBIOS_TYPE_OEM_STRINGS &&
            HasTestRunString(Table + Offset + Header->Length, Table + Next))
        {
            Scan->Present = TRUE;
        }

        if (Header->Handle >= Handle)
            Handle = Header->Handle + 1;
        if (Next - Offset > Scan->MaxSize)
            Scan->MaxSize = Next - Offset;
        Scan->Count++;

        if (Header->Type == SMBIOS_TYPE_END)
        {
            if (Handle > SMBIOS_MAX_HANDLE)
                return FALSE;
            Scan->EndOffset = Offset;
            Scan->EndSize = Next - Offset;
            Scan->NextHandle = (USHORT)Handle;
            return TRUE;
        }

        Offset = Next;
    }

    return FALSE;
}

static PUCHAR
BuildTable(const UCHAR* Table, PTABLE_SCAN Scan, PULONG NewLength)
{
    EFI_PHYSICAL_ADDRESS Address = 0xFFFFFFFF;
    ULONG OemSize = SMBIOS_OEM_STRINGS_LENGTH + sizeof(TestRunString) + 1;
    PUCHAR NewTable;
    PSMBIOS_HEADER Oem;

    *NewLength = Scan->EndOffset + OemSize + Scan->EndSize;
    if (SystemTable->BootServices->AllocatePages(AllocateMaxAddress,
                                                 EfiRuntimeServicesData,
                                                 EFI_SIZE_TO_PAGES(*NewLength),
                                                 &Address) != EFI_SUCCESS)
    {
        return NULL;
    }

    NewTable = (PUCHAR)(ULONG_PTR)Address;
    RtlCopyMemory(NewTable, Table, Scan->EndOffset);

    Oem = (PSMBIOS_HEADER)(NewTable + Scan->EndOffset);
    Oem->Type = SMBIOS_TYPE_OEM_STRINGS;
    Oem->Length = SMBIOS_OEM_STRINGS_LENGTH;
    Oem->Handle = Scan->NextHandle;
    NewTable[Scan->EndOffset + sizeof(SMBIOS_HEADER)] = 1;
    RtlCopyMemory(NewTable + Scan->EndOffset + SMBIOS_OEM_STRINGS_LENGTH, TestRunString, sizeof(TestRunString));
    NewTable[Scan->EndOffset + OemSize - 1] = 0;

    RtlCopyMemory(NewTable + Scan->EndOffset + OemSize, Table + Scan->EndOffset, Scan->EndSize);

    if (OemSize > Scan->MaxSize)
        Scan->MaxSize = OemSize;
    Scan->Count++;
    return NewTable;
}

static PVOID
AllocateEntryPoint(const VOID* EntryPoint, ULONG Length)
{
    PVOID Copy;

    if (SystemTable->BootServices->AllocatePool(EfiRuntimeServicesData, Length, &Copy) != EFI_SUCCESS)
        return NULL;

    RtlCopyMemory(Copy, EntryPoint, Length);
    return Copy;
}

static EFI_STATUS
Mark21(PSMBIOS_ENTRY_POINT EntryPoint)
{
    const ULONG IntermediateOffset = FIELD_OFFSET(SMBIOS_ENTRY_POINT, IntermediateAnchor);
    PSMBIOS_ENTRY_POINT NewEntryPoint;
    TABLE_SCAN Scan;
    PUCHAR NewTable;
    ULONG NewLength;

    if (EntryPoint->Length < sizeof(SMBIOS_ENTRY_POINT) || EntryPoint->Length > 32)
        return EFI_UNSUPPORTED;
    if (!ScanTable((const UCHAR*)(ULONG_PTR)EntryPoint->TableAddress, EntryPoint->TableLength, &Scan))
        return EFI_VOLUME_CORRUPTED;
    if (Scan.Present)
        return EFI_SUCCESS;

    NewTable = BuildTable((const UCHAR*)(ULONG_PTR)EntryPoint->TableAddress, &Scan, &NewLength);
    if (!NewTable || NewLength > MAXUSHORT)
        return EFI_OUT_OF_RESOURCES;

    NewEntryPoint = AllocateEntryPoint(EntryPoint, EntryPoint->Length);
    if (!NewEntryPoint)
        return EFI_OUT_OF_RESOURCES;

    NewEntryPoint->MaxStructureSize = (USHORT)(Scan.MaxSize > EntryPoint->MaxStructureSize ?
                                               Scan.MaxSize : EntryPoint->MaxStructureSize);
    NewEntryPoint->TableLength = (USHORT)NewLength;
    NewEntryPoint->TableAddress = (ULONG)(ULONG_PTR)NewTable;
    NewEntryPoint->NumberOfStructures = Scan.Count;
    NewEntryPoint->IntermediateChecksum = 0;
    NewEntryPoint->IntermediateChecksum =
        Checksum((const UCHAR*)NewEntryPoint + IntermediateOffset, EntryPoint->Length - IntermediateOffset);
    NewEntryPoint->Checksum = 0;
    NewEntryPoint->Checksum = Checksum((const UCHAR*)NewEntryPoint, EntryPoint->Length);

    return SystemTable->BootServices->InstallConfigurationTable(&SmbiosGuid, NewEntryPoint);
}

static EFI_STATUS
Mark30(PSMBIOS3_ENTRY_POINT EntryPoint)
{
    PSMBIOS3_ENTRY_POINT NewEntryPoint;
    TABLE_SCAN Scan;
    PUCHAR NewTable;
    ULONG NewLength;

    if (EntryPoint->Length < sizeof(SMBIOS3_ENTRY_POINT) || EntryPoint->Length > 32)
        return EFI_UNSUPPORTED;
    if (!ScanTable((const UCHAR*)(ULONG_PTR)EntryPoint->TableAddress, EntryPoint->MaxStructureSize, &Scan))
        return EFI_VOLUME_CORRUPTED;
    if (Scan.Present)
        return EFI_SUCCESS;

    NewTable = BuildTable((const UCHAR*)(ULONG_PTR)EntryPoint->TableAddress, &Scan, &NewLength);
    if (!NewTable)
        return EFI_OUT_OF_RESOURCES;

    NewEntryPoint = AllocateEntryPoint(EntryPoint, EntryPoint->Length);
    if (!NewEntryPoint)
        return EFI_OUT_OF_RESOURCES;

    NewEntryPoint->MaxStructureSize = NewLength;
    NewEntryPoint->TableAddress = (ULONGLONG)(ULONG_PTR)NewTable;
    NewEntryPoint->Checksum = 0;
    NewEntryPoint->Checksum = Checksum((const UCHAR*)NewEntryPoint, EntryPoint->Length);

    return SystemTable->BootServices->InstallConfigurationTable(&Smbios3Guid, NewEntryPoint);
}

EFI_STATUS
EFIAPI
TestRunEntry(
    _In_ EFI_HANDLE ImageHandle,
    _In_ EFI_SYSTEM_TABLE* Table)
{
    PSMBIOS3_ENTRY_POINT EntryPoint30;
    PSMBIOS_ENTRY_POINT EntryPoint21;
    EFI_STATUS Status = EFI_NOT_FOUND;

    UNREFERENCED_PARAMETER(ImageHandle);
    SystemTable = Table;

    EntryPoint30 = FindTable(&Smbios3Guid);
    EntryPoint21 = FindTable(&SmbiosGuid);

    if (EntryPoint30 && RtlEqualMemory(EntryPoint30->Anchor, "_SM3_", 5))
    {
        Status = Mark30(EntryPoint30);
        if (EFI_ERROR(Status))
            goto Done;
    }

    if (EntryPoint21 && RtlEqualMemory(EntryPoint21->Anchor, "_SM_", 4))
        Status = Mark21(EntryPoint21);

Done:
    Say(EFI_ERROR(Status) ? L"TESTRUN_SMBIOS_FAILED\r\n" : L"TESTRUN_SMBIOS_OK\r\n");
    return Status;
}
