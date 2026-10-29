/*
 * PROJECT:     OpenNT Boot Loader
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Boot entry enumeration from the BCD store
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif.ing@outlook.com>
 */

#include <bl.h>

static
ULONG
BmEnumerateList(
    _In_ ULONG List,
    _Out_writes_(MaxEntries) PBM_ENTRY Entries,
    _In_ ULONG MaxEntries,
    _Out_ PULONG DefaultEntry)
{
    BCD_OBJECT BootMgr;
    WCHAR DefaultId[BCD_ID_CHARS];
    WCHAR Id[BCD_ID_CHARS];
    PBM_ENTRY Entry;
    ULONG Count = 0;
    ULONG Index;

    *DefaultEntry = MAXULONG;

    if (!BcdOpenObject(BCD_ID_BOOTMGR, &BootMgr) || BootMgr.Type != BCD_OBJECT_BOOTMGR)
        return 0;

    if (!BcdGetObjectId(&BootMgr, BcdBootMgrObject_DefaultObject, 0, DefaultId))
        DefaultId[0] = UNICODE_NULL;

    for (Index = 0;
         Count < MaxEntries &&
         BcdGetObjectId(&BootMgr, List, Index, Id);
         Index++)
    {
        Entry = &Entries[Count];

        if (!BcdOpenObject(Id, &Entry->Object) || Entry->Object.Type != BCD_OBJECT_OSLOADER)
            continue;

        if (!BcdGetString(&Entry->Object,
                          BcdLibraryString_Description,
                          Entry->Description,
                          RTL_NUMBER_OF(Entry->Description)))
        {
            RtlStringCchCopyW(Entry->Description, RTL_NUMBER_OF(Entry->Description), Id);
        }

        RtlStringCchCopyW(Entry->Id, RTL_NUMBER_OF(Entry->Id), Id);

        if (_wcsicmp(Id, DefaultId) == 0)
            *DefaultEntry = Count;

        Count++;
    }

    return Count;
}

ULONG
BmEnumerateEntries(
    _Out_writes_(MaxEntries) PBM_ENTRY Entries,
    _In_ ULONG MaxEntries,
    _Out_ PULONG DefaultEntry)
{
    ULONG Count;

    Count = BmEnumerateList(BcdBootMgrObjectList_DisplayOrder, Entries, MaxEntries, DefaultEntry);
    if (*DefaultEntry >= Count)
        *DefaultEntry = 0;

    return Count;
}

ULONG
BmEnumerateToolEntries(
    _Out_writes_(MaxEntries) PBM_ENTRY Entries,
    _In_ ULONG MaxEntries,
    _Out_ PULONG DefaultEntry)
{
    return BmEnumerateList(BcdBootMgrObjectList_ToolsDisplayOrder, Entries, MaxEntries, DefaultEntry);
}

BOOLEAN
BmGetDescription(
    _Out_writes_z_(Chars) PWSTR Description,
    _In_ ULONG Chars)
{
    BCD_OBJECT BootMgr;

    return BcdOpenObject(BCD_ID_BOOTMGR, &BootMgr) &&
           BcdGetString(&BootMgr, BcdLibraryString_Description, Description, Chars);
}

