/*
 * PROJECT:     OpenNT IF Monitor DLL
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NetSh interface ipv6 context
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193@gmail.com>
 */

#include "precomp.h"

#include <ws2tcpip.h>
#include <netioapi.h>

#define NDEBUG
#include <debug.h>

#include "guid.h"
#include "resource.h"

static FN_HANDLE_CMD Ipv6AddAddress;
static FN_HANDLE_CMD Ipv6AddRoute;
static FN_HANDLE_CMD Ipv6AddDnsServers;
static FN_HANDLE_CMD Ipv6DeleteAddress;
static FN_HANDLE_CMD Ipv6DeleteRoute;
static FN_HANDLE_CMD Ipv6DeleteDnsServers;
static FN_HANDLE_CMD Ipv6AddNeighbors;
static FN_HANDLE_CMD Ipv6DeleteNeighbors;
static FN_HANDLE_CMD Ipv6SetInterface;
static FN_HANDLE_CMD Ipv6ShowAddresses;
static FN_HANDLE_CMD Ipv6ShowRoute;
static FN_HANDLE_CMD Ipv6ShowInterfaces;
static FN_HANDLE_CMD Ipv6ShowNeighbors;
static FN_HANDLE_CMD Ipv6ShowDnsServers;
static FN_HANDLE_CMD Ipv6ShowPrefixPolicies;

static
CMD_ENTRY
Ipv6AddCommands[] =
{
    {L"address", Ipv6AddAddress, IDS_HLP_IPV6_ADD_ADDRESS, IDS_HLP_IPV6_ADD_ADDRESS_EX, 0},
    {L"dnsservers", Ipv6AddDnsServers, IDS_HLP_IPV6_ADD_DNSSERVERS, IDS_HLP_IPV6_ADD_DNSSERVERS_EX, 0},
    {L"neighbors", Ipv6AddNeighbors, IDS_HLP_IPV6_ADD_NEIGHBORS, IDS_HLP_IPV6_ADD_NEIGHBORS_EX, 0},
    {L"route", Ipv6AddRoute, IDS_HLP_IPV6_ADD_ROUTE, IDS_HLP_IPV6_ADD_ROUTE_EX, 0}
};

static
CMD_ENTRY
Ipv6DeleteCommands[] =
{
    {L"address", Ipv6DeleteAddress, IDS_HLP_IPV6_DELETE_ADDRESS, IDS_HLP_IPV6_DELETE_ADDRESS_EX, 0},
    {L"dnsservers", Ipv6DeleteDnsServers, IDS_HLP_IPV6_DELETE_DNSSERVERS, IDS_HLP_IPV6_DELETE_DNSSERVERS_EX, 0},
    {L"neighbors", Ipv6DeleteNeighbors, IDS_HLP_IPV6_DELETE_NEIGHBORS, IDS_HLP_IPV6_DELETE_NEIGHBORS_EX, 0},
    {L"route", Ipv6DeleteRoute, IDS_HLP_IPV6_DELETE_ROUTE, IDS_HLP_IPV6_DELETE_ROUTE_EX, 0}
};

static
CMD_ENTRY
Ipv6SetCommands[] =
{
    {L"interface", Ipv6SetInterface, IDS_HLP_IPV6_SET_INTERFACE, IDS_HLP_IPV6_SET_INTERFACE_EX, 0}
};

static
CMD_ENTRY
Ipv6ShowCommands[] =
{
    {L"addresses", Ipv6ShowAddresses, IDS_HLP_IPV6_SHOW_ADDRESSES, IDS_HLP_IPV6_SHOW_ADDRESSES_EX, 0},
    {L"dnsservers", Ipv6ShowDnsServers, IDS_HLP_IPV6_SHOW_DNSSERVERS, IDS_HLP_IPV6_SHOW_DNSSERVERS_EX, 0},
    {L"interfaces", Ipv6ShowInterfaces, IDS_HLP_IPV6_SHOW_INTERFACES, IDS_HLP_IPV6_SHOW_INTERFACES_EX, 0},
    {L"neighbors", Ipv6ShowNeighbors, IDS_HLP_IPV6_SHOW_NEIGHBORS, IDS_HLP_IPV6_SHOW_NEIGHBORS_EX, 0},
    {L"prefixpolicies", Ipv6ShowPrefixPolicies, IDS_HLP_IPV6_SHOW_PREFIXPOLICIES, IDS_HLP_IPV6_SHOW_PREFIXPOLICIES_EX, 0},
    {L"route", Ipv6ShowRoute, IDS_HLP_IPV6_SHOW_ROUTE, IDS_HLP_IPV6_SHOW_ROUTE_EX, 0}
};

static
CMD_GROUP_ENTRY
Ipv6Groups[] =
{
    {L"add", IDS_HLP_IPV6_ADD, ARRAYSIZE(Ipv6AddCommands), 0, Ipv6AddCommands, NULL},
    {L"delete", IDS_HLP_IPV6_DELETE, ARRAYSIZE(Ipv6DeleteCommands), 0, Ipv6DeleteCommands, NULL},
    {L"set", IDS_HLP_IPV6_SET, ARRAYSIZE(Ipv6SetCommands), 0, Ipv6SetCommands, NULL},
    {L"show", IDS_HLP_IPV6_SHOW, ARRAYSIZE(Ipv6ShowCommands), 0, Ipv6ShowCommands, NULL},
};

static
PIP_ADAPTER_ADDRESSES
Ipv6GetAdapters(VOID)
{
    PIP_ADAPTER_ADDRESSES pList;
    ULONG Size = 16384, Error;

    for (;;)
    {
        pList = HeapAlloc(GetProcessHeap(), 0, Size);
        if (pList == NULL)
            return NULL;
        Error = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, NULL, pList, &Size);
        if (Error == ERROR_SUCCESS)
            return pList;
        HeapFree(GetProcessHeap(), 0, pList);
        if (Error != ERROR_BUFFER_OVERFLOW)
            return NULL;
    }
}

static
VOID
Ipv6InterfaceName(PIP_ADAPTER_ADDRESSES pList, NET_IFINDEX Index, PWSTR Name, SIZE_T Count)
{
    for (; pList; pList = pList->Next)
    {
        if (pList->Ipv6IfIndex == Index || pList->IfIndex == Index)
        {
            if (pList->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
                StringCchPrintfW(Name, Count, L"Loopback Pseudo-Interface %lu", Index);
            else
                StringCchCopyW(Name, Count, pList->FriendlyName);
            return;
        }
    }
    StringCchPrintfW(Name, Count, L"%lu", Index);
}

static
DWORD
Ipv6ResolveInterface(PCWSTR Text, NET_IFINDEX *Index)
{
    PIP_ADAPTER_ADDRESSES pList, pAdapter;
    WCHAR Name[256];
    PWSTR End;
    DWORD Value = wcstoul(Text, &End, 10);

    if (*Text && !*End)
    {
        *Index = Value;
        return ERROR_SUCCESS;
    }

    pList = Ipv6GetAdapters();
    for (pAdapter = pList; pAdapter; pAdapter = pAdapter->Next)
    {
        Ipv6InterfaceName(pList, pAdapter->Ipv6IfIndex ? pAdapter->Ipv6IfIndex : pAdapter->IfIndex, Name, ARRAYSIZE(Name));
        if (!_wcsicmp(Name, Text))
        {
            *Index = pAdapter->Ipv6IfIndex ? pAdapter->Ipv6IfIndex : pAdapter->IfIndex;
            HeapFree(GetProcessHeap(), 0, pList);
            return ERROR_SUCCESS;
        }
    }
    if (pList)
        HeapFree(GetProcessHeap(), 0, pList);
    return ERROR_NOT_FOUND;
}

static
BOOL
Ipv6ParseAddress(PCWSTR Text, PIN6_ADDR Address, PUINT8 PrefixLength, UINT8 DefaultLength)
{
    WCHAR Copy[INET6_ADDRSTRLEN + 8];
    PWSTR Slash;
    PCWSTR Terminator;
    ULONG Length = DefaultLength;

    if (FAILED(StringCchCopyW(Copy, ARRAYSIZE(Copy), Text)))
        return FALSE;
    Slash = wcschr(Copy, L'/');
    if (Slash)
    {
        *Slash++ = UNICODE_NULL;
        Length = wcstoul(Slash, NULL, 10);
        if (Length > 128)
            return FALSE;
    }
    if (RtlIpv6StringToAddressW(Copy, &Terminator, Address) != 0 || *Terminator)
        return FALSE;
    if (PrefixLength)
        *PrefixLength = (UINT8)Length;
    return TRUE;
}

static
VOID
Ipv6FormatLifetime(ULONG Seconds, PWSTR Buffer, SIZE_T Count)
{
    ULONG Days = Seconds / 86400, Hours = (Seconds / 3600) % 24, Minutes = (Seconds / 60) % 60, Rest = Seconds % 60;
    WCHAR Part[16];

    if (Seconds == 0xFFFFFFFF)
    {
        StringCchCopyW(Buffer, Count, L"infinite");
        return;
    }
    Buffer[0] = UNICODE_NULL;
    if (Days)
    {
        StringCchPrintfW(Part, ARRAYSIZE(Part), L"%lud", Days);
        StringCchCatW(Buffer, Count, Part);
    }
    if (Hours)
    {
        StringCchPrintfW(Part, ARRAYSIZE(Part), L"%luh", Hours);
        StringCchCatW(Buffer, Count, Part);
    }
    if (Minutes)
    {
        StringCchPrintfW(Part, ARRAYSIZE(Part), L"%lum", Minutes);
        StringCchCatW(Buffer, Count, Part);
    }
    if (Rest || !Buffer[0])
    {
        StringCchPrintfW(Part, ARRAYSIZE(Part), L"%lus", Rest);
        StringCchCatW(Buffer, Count, Part);
    }
}

static
DWORD
Ipv6MatchTags(LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount, PTAG_TYPE pTags, DWORD dwTagCount, PDWORD *ppTagType)
{
    DWORD i, Error;

    *ppTagType = HeapAlloc(GetProcessHeap(), 0, max(dwArgCount - dwCurrentIndex, 1) * sizeof(DWORD));
    if (*ppTagType == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;
    Error = MatchTagsInCmdLine(hDllInstance, argv, dwCurrentIndex, dwArgCount, pTags, dwTagCount, *ppTagType);
    if (Error == ERROR_SUCCESS)
    {
        for (i = 0; i < dwTagCount; i++)
        {
            if (pTags[i].dwRequired == NS_REQ_PRESENT && !pTags[i].bPresent)
                Error = ERROR_SHOW_USAGE;
        }
        for (i = 0; i < dwArgCount - dwCurrentIndex; i++)
        {
            if ((*ppTagType)[i] == (DWORD)-1)
                Error = ERROR_SHOW_USAGE;
        }
    }
    if (Error != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, *ppTagType);
        *ppTagType = NULL;
    }
    return Error;
}

static DWORD Ipv6OpenInterfaceKey(NET_IFINDEX Index, REGSAM Access, PHKEY Key);

static
BOOL
Ipv6ParseStore(PCWSTR Value, PBOOL Persistent)
{
    if (!_wcsicmp(Value, L"active"))
        *Persistent = FALSE;
    else if (!_wcsicmp(Value, L"persistent"))
        *Persistent = TRUE;
    else
        return FALSE;
    return TRUE;
}

static
DWORD
Ipv6OpenPersistentKey(NET_IFINDEX Index, PHKEY Key)
{
    HKEY Interface;
    DWORD Error = Ipv6OpenInterfaceKey(Index, KEY_CREATE_SUB_KEY, &Interface);

    if (Error != ERROR_SUCCESS)
        return Error;
    Error = RegCreateKeyExW(Interface, L"PersistentStore", 0, NULL, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, Key, NULL);
    RegCloseKey(Interface);
    return Error;
}

static
VOID
Ipv6PersistEntry(NET_IFINDEX Index, PCWSTR List, PCWSTR Entry, SIZE_T KeyLength, BOOL bAdd)
{
    WCHAR Current[4096], Updated[4096];
    DWORD Size = sizeof(Current) - 2 * sizeof(WCHAR), Type, Used = 0;
    PCWSTR Item;
    HKEY Key;

    if (Ipv6OpenPersistentKey(Index, &Key) != ERROR_SUCCESS)
        return;
    if (RegQueryValueExW(Key, List, NULL, &Type, (PBYTE)Current, &Size) != ERROR_SUCCESS || Type != REG_MULTI_SZ)
        Size = 0;
    Current[Size / sizeof(WCHAR)] = UNICODE_NULL;
    Current[Size / sizeof(WCHAR) + 1] = UNICODE_NULL;

    for (Item = Current; *Item; Item += wcslen(Item) + 1)
    {
        SIZE_T Length = wcslen(Item) + 1;

        if (!_wcsnicmp(Item, Entry, KeyLength) && (Item[KeyLength] == L' ' || !Item[KeyLength]))
            continue;
        if (Used + Length + 1 >= ARRAYSIZE(Updated))
            break;
        RtlCopyMemory(&Updated[Used], Item, Length * sizeof(WCHAR));
        Used += (DWORD)Length;
    }
    if (bAdd && Used + wcslen(Entry) + 2 < ARRAYSIZE(Updated))
    {
        StringCchCopyW(&Updated[Used], ARRAYSIZE(Updated) - Used, Entry);
        Used += (DWORD)wcslen(Entry) + 1;
    }
    Updated[Used] = UNICODE_NULL;
    if (Used)
        RegSetValueExW(Key, List, 0, REG_MULTI_SZ, (const BYTE *)Updated, (Used + 1) * sizeof(WCHAR));
    else
        RegDeleteValueW(Key, List);
    RegCloseKey(Key);
}

static
VOID
Ipv6PersistValue(NET_IFINDEX Index, PCWSTR Name, DWORD Value)
{
    HKEY Key;

    if (Ipv6OpenPersistentKey(Index, &Key) != ERROR_SUCCESS)
        return;
    RegSetValueExW(Key, Name, 0, REG_DWORD, (const BYTE *)&Value, sizeof(Value));
    RegCloseKey(Key);
}

static
VOID
Ipv6FormatMac(const UCHAR *Address, ULONG Length, PWSTR Buffer, SIZE_T Count)
{
    ULONG k;

    Buffer[0] = UNICODE_NULL;
    for (k = 0; k < Length && k < 8; k++)
    {
        WCHAR Byte[4];

        StringCchPrintfW(Byte, ARRAYSIZE(Byte), k ? L"-%02x" : L"%02x", Address[k]);
        StringCchCatW(Buffer, Count, Byte);
    }
}

static
BOOL
Ipv6ParseMac(PCWSTR Text, PUCHAR Address, PULONG Length)
{
    ULONG Count = 0;

    while (*Text && Count < 8)
    {
        PWSTR End;
        ULONG Byte = wcstoul(Text, &End, 16);

        if (End == Text || End - Text > 2 || Byte > 0xFF)
            return FALSE;
        Address[Count++] = (UCHAR)Byte;
        Text = End;
        if (*Text == L'-' || *Text == L':')
            Text++;
        else if (*Text)
            return FALSE;
    }
    *Length = Count;
    return Count && !*Text;
}

static
DWORD
Ipv6Address(LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount, BOOL bAdd)
{
    TAG_TYPE Tags[] = {{L"interface", NS_REQ_PRESENT, FALSE},
                       {L"address", NS_REQ_PRESENT, FALSE},
                       {L"validlifetime", NS_REQ_ZERO, FALSE},
                       {L"preferredlifetime", NS_REQ_ZERO, FALSE},
                       {L"store", NS_REQ_ZERO, FALSE}};
    MIB_UNICASTIPADDRESS_ROW Row;
    PDWORD pTagType;
    DWORD i, Error;
    UINT8 PrefixLength = 0xFF;
    BOOL Persistent = TRUE;

    Error = Ipv6MatchTags(argv, dwCurrentIndex, dwArgCount, Tags, ARRAYSIZE(Tags), &pTagType);
    if (Error != ERROR_SUCCESS)
        return Error;

    InitializeUnicastIpAddressEntry(&Row);
    Row.Address.Ipv6.sin6_family = AF_INET6;
    for (i = 0; i < dwArgCount - dwCurrentIndex && Error == ERROR_SUCCESS; i++)
    {
        PCWSTR Value = argv[dwCurrentIndex + i];

        switch (pTagType[i])
        {
            case 0:
                if (Ipv6ResolveInterface(Value, &Row.InterfaceIndex) != ERROR_SUCCESS)
                {
                    PrintMessageFromModule(hDllInstance, IDS_ERROR_INVALID_INTERFACE, Value);
                    Error = ERROR_SUPPRESS_OUTPUT;
                }
                break;
            case 1:
                if (!Ipv6ParseAddress(Value, &Row.Address.Ipv6.sin6_addr, &PrefixLength, 0xFF))
                {
                    PrintMessageFromModule(hDllInstance, IDS_ERROR_BAD_VALUE, Value, Tags[1].pwszTag);
                    Error = ERROR_SUPPRESS_OUTPUT;
                }
                break;
            case 2:
            case 3:
            {
                ULONG Lifetime = _wcsicmp(Value, L"infinite") ? wcstoul(Value, NULL, 10) : 0xFFFFFFFF;

                if (pTagType[i] == 2)
                    Row.ValidLifetime = Lifetime;
                else
                    Row.PreferredLifetime = Lifetime;
                break;
            }
            case 4:
                if (!Ipv6ParseStore(Value, &Persistent))
                {
                    PrintMessageFromModule(hDllInstance, IDS_ERROR_BAD_VALUE, Value, Tags[4].pwszTag);
                    Error = ERROR_SUPPRESS_OUTPUT;
                }
                break;
            default:
                break;
        }
    }
    HeapFree(GetProcessHeap(), 0, pTagType);
    if (Error != ERROR_SUCCESS)
        return Error;

    Row.OnLinkPrefixLength = PrefixLength == 0xFF ? 64 : PrefixLength;
    Error = bAdd ? CreateUnicastIpAddressEntry(&Row) : DeleteUnicastIpAddressEntry(&Row);
    if (Persistent && (Error == ERROR_SUCCESS || (!bAdd && Error == ERROR_INVALID_PARAMETER)))
    {
        WCHAR Text[INET6_ADDRSTRLEN], Entry[128];

        RtlIpv6AddressToStringW(&Row.Address.Ipv6.sin6_addr, Text);
        StringCchPrintfW(Entry, ARRAYSIZE(Entry), L"%s %u %lu %lu", Text, Row.OnLinkPrefixLength, Row.ValidLifetime,
                         Row.PreferredLifetime);
        Ipv6PersistEntry(Row.InterfaceIndex, L"Addresses", Entry, wcslen(Text), bAdd);
        if (!bAdd)
            Error = ERROR_SUCCESS;
    }
    return Error;
}

static
DWORD
WINAPI
Ipv6AddAddress(LPCWSTR pwszMachine, LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount,
               DWORD dwFlags, LPCVOID pvData, BOOL *pbDone)
{
    return Ipv6Address(argv, dwCurrentIndex, dwArgCount, TRUE);
}

static
DWORD
WINAPI
Ipv6DeleteAddress(LPCWSTR pwszMachine, LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount,
                  DWORD dwFlags, LPCVOID pvData, BOOL *pbDone)
{
    return Ipv6Address(argv, dwCurrentIndex, dwArgCount, FALSE);
}

static
DWORD
Ipv6Route(LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount, BOOL bAdd)
{
    TAG_TYPE Tags[] = {{L"prefix", NS_REQ_PRESENT, FALSE},
                       {L"interface", NS_REQ_PRESENT, FALSE},
                       {L"nexthop", NS_REQ_ZERO, FALSE},
                       {L"metric", NS_REQ_ZERO, FALSE},
                       {L"store", NS_REQ_ZERO, FALSE},
                       {L"publish", NS_REQ_ZERO, FALSE}};
    MIB_IPFORWARD_ROW2 Row;
    PDWORD pTagType;
    DWORD i, Error;
    BOOL Persistent = TRUE;

    Error = Ipv6MatchTags(argv, dwCurrentIndex, dwArgCount, Tags, ARRAYSIZE(Tags), &pTagType);
    if (Error != ERROR_SUCCESS)
        return Error;

    InitializeIpForwardEntry(&Row);
    Row.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
    Row.NextHop.Ipv6.sin6_family = AF_INET6;
    for (i = 0; i < dwArgCount - dwCurrentIndex && Error == ERROR_SUCCESS; i++)
    {
        PCWSTR Value = argv[dwCurrentIndex + i];

        switch (pTagType[i])
        {
            case 0:
                if (!Ipv6ParseAddress(Value, &Row.DestinationPrefix.Prefix.Ipv6.sin6_addr,
                                      &Row.DestinationPrefix.PrefixLength, 128))
                {
                    PrintMessageFromModule(hDllInstance, IDS_ERROR_BAD_VALUE, Value, Tags[0].pwszTag);
                    Error = ERROR_SUPPRESS_OUTPUT;
                }
                break;
            case 1:
                if (Ipv6ResolveInterface(Value, &Row.InterfaceIndex) != ERROR_SUCCESS)
                {
                    PrintMessageFromModule(hDllInstance, IDS_ERROR_INVALID_INTERFACE, Value);
                    Error = ERROR_SUPPRESS_OUTPUT;
                }
                break;
            case 2:
                if (!Ipv6ParseAddress(Value, &Row.NextHop.Ipv6.sin6_addr, NULL, 128))
                {
                    PrintMessageFromModule(hDllInstance, IDS_ERROR_BAD_VALUE, Value, Tags[2].pwszTag);
                    Error = ERROR_SUPPRESS_OUTPUT;
                }
                break;
            case 3:
                Row.Metric = wcstoul(Value, NULL, 10);
                break;
            case 4:
                if (!Ipv6ParseStore(Value, &Persistent))
                {
                    PrintMessageFromModule(hDllInstance, IDS_ERROR_BAD_VALUE, Value, Tags[4].pwszTag);
                    Error = ERROR_SUPPRESS_OUTPUT;
                }
                break;
            case 5:
                if (!_wcsicmp(Value, L"yes") || !_wcsicmp(Value, L"age"))
                    Row.Publish = TRUE;
                else if (!_wcsicmp(Value, L"no"))
                    Row.Publish = FALSE;
                else
                {
                    PrintMessageFromModule(hDllInstance, IDS_ERROR_BAD_VALUE, Value, Tags[5].pwszTag);
                    Error = ERROR_SUPPRESS_OUTPUT;
                }
                break;
            default:
                break;
        }
    }
    HeapFree(GetProcessHeap(), 0, pTagType);
    if (Error != ERROR_SUCCESS)
        return Error;

    Error = bAdd ? CreateIpForwardEntry2(&Row) : DeleteIpForwardEntry2(&Row);
    if (Persistent && (Error == ERROR_SUCCESS || (!bAdd && Error == ERROR_NOT_FOUND)))
    {
        WCHAR Prefix[INET6_ADDRSTRLEN], NextHop[INET6_ADDRSTRLEN], Entry[160];
        SIZE_T KeyLength;

        RtlIpv6AddressToStringW(&Row.DestinationPrefix.Prefix.Ipv6.sin6_addr, Prefix);
        RtlIpv6AddressToStringW(&Row.NextHop.Ipv6.sin6_addr, NextHop);
        StringCchPrintfW(Entry, ARRAYSIZE(Entry), L"%s/%u %s", Prefix, Row.DestinationPrefix.PrefixLength, NextHop);
        KeyLength = wcslen(Entry);
        StringCchPrintfW(Entry + KeyLength, ARRAYSIZE(Entry) - KeyLength, L" %lu", Row.Metric);
        Ipv6PersistEntry(Row.InterfaceIndex, L"Routes", Entry, KeyLength, bAdd);
        if (!bAdd)
            Error = ERROR_SUCCESS;
    }
    return Error;
}

static
DWORD
WINAPI
Ipv6AddRoute(LPCWSTR pwszMachine, LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount,
             DWORD dwFlags, LPCVOID pvData, BOOL *pbDone)
{
    return Ipv6Route(argv, dwCurrentIndex, dwArgCount, TRUE);
}

static
DWORD
WINAPI
Ipv6DeleteRoute(LPCWSTR pwszMachine, LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount,
                DWORD dwFlags, LPCVOID pvData, BOOL *pbDone)
{
    return Ipv6Route(argv, dwCurrentIndex, dwArgCount, FALSE);
}

static
DWORD
Ipv6Neighbors(LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount, BOOL bAdd)
{
    TAG_TYPE Tags[] = {{L"interface", NS_REQ_PRESENT, FALSE},
                       {L"address", bAdd ? NS_REQ_PRESENT : NS_REQ_ZERO, FALSE},
                       {L"neighbor", bAdd ? NS_REQ_PRESENT : NS_REQ_ZERO, FALSE},
                       {L"store", NS_REQ_ZERO, FALSE}};
    MIB_IPNET_ROW2 Row;
    PDWORD pTagType;
    DWORD i, Error;
    BOOL Persistent = TRUE, bAddress = FALSE;

    Error = Ipv6MatchTags(argv, dwCurrentIndex, dwArgCount, Tags, ARRAYSIZE(Tags), &pTagType);
    if (Error != ERROR_SUCCESS)
        return Error;

    memset(&Row, 0, sizeof(Row));
    Row.Address.Ipv6.sin6_family = AF_INET6;
    for (i = 0; i < dwArgCount - dwCurrentIndex && Error == ERROR_SUCCESS; i++)
    {
        PCWSTR Value = argv[dwCurrentIndex + i];

        switch (pTagType[i])
        {
            case 0:
                if (Ipv6ResolveInterface(Value, &Row.InterfaceIndex) != ERROR_SUCCESS)
                {
                    PrintMessageFromModule(hDllInstance, IDS_ERROR_INVALID_INTERFACE, Value);
                    Error = ERROR_SUPPRESS_OUTPUT;
                }
                break;
            case 1:
                if (!Ipv6ParseAddress(Value, &Row.Address.Ipv6.sin6_addr, NULL, 128))
                {
                    PrintMessageFromModule(hDllInstance, IDS_ERROR_BAD_VALUE, Value, Tags[1].pwszTag);
                    Error = ERROR_SUPPRESS_OUTPUT;
                }
                bAddress = TRUE;
                break;
            case 2:
                if (!Ipv6ParseMac(Value, Row.PhysicalAddress, &Row.PhysicalAddressLength))
                {
                    PrintMessageFromModule(hDllInstance, IDS_ERROR_BAD_VALUE, Value, Tags[2].pwszTag);
                    Error = ERROR_SUPPRESS_OUTPUT;
                }
                break;
            case 3:
                if (!Ipv6ParseStore(Value, &Persistent))
                {
                    PrintMessageFromModule(hDllInstance, IDS_ERROR_BAD_VALUE, Value, Tags[3].pwszTag);
                    Error = ERROR_SUPPRESS_OUTPUT;
                }
                break;
            default:
                break;
        }
    }
    HeapFree(GetProcessHeap(), 0, pTagType);
    if (Error != ERROR_SUCCESS)
        return Error;

    if (!bAdd && !bAddress)
    {
        HKEY Key;

        Error = FlushIpNetTable2(AF_INET6, Row.InterfaceIndex);
        if (Error == ERROR_SUCCESS && Persistent && Ipv6OpenPersistentKey(Row.InterfaceIndex, &Key) == ERROR_SUCCESS)
        {
            RegDeleteValueW(Key, L"Neighbors");
            RegCloseKey(Key);
        }
    }
    else
    {
        Error = bAdd ? CreateIpNetEntry2(&Row) : DeleteIpNetEntry2(&Row);
        if (Persistent && (Error == ERROR_SUCCESS || (!bAdd && Error == ERROR_NOT_FOUND)))
        {
            WCHAR Text[INET6_ADDRSTRLEN], Entry[128];
            SIZE_T KeyLength;

            RtlIpv6AddressToStringW(&Row.Address.Ipv6.sin6_addr, Text);
            KeyLength = wcslen(Text);
            StringCchPrintfW(Entry, ARRAYSIZE(Entry), L"%s ", Text);
            Ipv6FormatMac(Row.PhysicalAddress, Row.PhysicalAddressLength, Entry + KeyLength + 1,
                          ARRAYSIZE(Entry) - KeyLength - 1);
            Ipv6PersistEntry(Row.InterfaceIndex, L"Neighbors", Entry, KeyLength, bAdd);
            if (!bAdd)
                Error = ERROR_SUCCESS;
        }
    }
    if (Error == ERROR_SUCCESS && !bAdd)
        PrintMessageFromModule(hDllInstance, IDS_IPV6_OK);
    return Error;
}

static
DWORD
WINAPI
Ipv6AddNeighbors(LPCWSTR pwszMachine, LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount,
                 DWORD dwFlags, LPCVOID pvData, BOOL *pbDone)
{
    return Ipv6Neighbors(argv, dwCurrentIndex, dwArgCount, TRUE);
}

static
DWORD
WINAPI
Ipv6DeleteNeighbors(LPCWSTR pwszMachine, LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount,
                    DWORD dwFlags, LPCVOID pvData, BOOL *pbDone)
{
    return Ipv6Neighbors(argv, dwCurrentIndex, dwArgCount, FALSE);
}

static
DWORD
WINAPI
Ipv6SetInterface(LPCWSTR pwszMachine, LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount,
                 DWORD dwFlags, LPCVOID pvData, BOOL *pbDone)
{
    static PCWSTR Values[] = {L"Metric", L"Mtu", L"SitePrefixLength", L"RouterDiscovery", L"DadTransmits",
                              L"BaseReachableTime", L"RetransmitTime", L"Forwarding", L"Advertise",
                              L"ManagedAddress", L"OtherStateful", L"WeakHostSend", L"WeakHostReceive",
                              L"IgnoreDefaultRoutes", L"AdvertiseDefaultRoute"};
    TAG_TYPE Tags[] = {{L"interface", NS_REQ_PRESENT, FALSE},
                       {L"metric", NS_REQ_ZERO, FALSE},
                       {L"mtu", NS_REQ_ZERO, FALSE},
                       {L"siteprefixlength", NS_REQ_ZERO, FALSE},
                       {L"routerdiscovery", NS_REQ_ZERO, FALSE},
                       {L"dadtransmits", NS_REQ_ZERO, FALSE},
                       {L"basereachabletime", NS_REQ_ZERO, FALSE},
                       {L"retransmittime", NS_REQ_ZERO, FALSE},
                       {L"forwarding", NS_REQ_ZERO, FALSE},
                       {L"advertise", NS_REQ_ZERO, FALSE},
                       {L"managedaddress", NS_REQ_ZERO, FALSE},
                       {L"otherstateful", NS_REQ_ZERO, FALSE},
                       {L"weakhostsend", NS_REQ_ZERO, FALSE},
                       {L"weakhostreceive", NS_REQ_ZERO, FALSE},
                       {L"ignoredefaultroutes", NS_REQ_ZERO, FALSE},
                       {L"advertisedefaultroute", NS_REQ_ZERO, FALSE},
                       {L"store", NS_REQ_ZERO, FALSE}};
    DWORD Settings[ARRAYSIZE(Values)];
    BOOL Present[ARRAYSIZE(Values)] = {FALSE};
    MIB_IPINTERFACE_ROW Row;
    PDWORD pTagType;
    DWORD i, Error;
    BOOL Persistent = TRUE;

    Error = Ipv6MatchTags(argv, dwCurrentIndex, dwArgCount, Tags, ARRAYSIZE(Tags), &pTagType);
    if (Error != ERROR_SUCCESS)
        return Error;

    InitializeIpInterfaceEntry(&Row);
    Row.Family = AF_INET6;
    for (i = 0; i < dwArgCount - dwCurrentIndex && Error == ERROR_SUCCESS; i++)
    {
        PCWSTR Value = argv[dwCurrentIndex + i];
        DWORD Tag = pTagType[i];
        PWSTR End;

        if (Tag == 0)
        {
            if (Ipv6ResolveInterface(Value, &Row.InterfaceIndex) != ERROR_SUCCESS)
            {
                PrintMessageFromModule(hDllInstance, IDS_ERROR_INVALID_INTERFACE, Value);
                Error = ERROR_SUPPRESS_OUTPUT;
            }
        }
        else if (Tag == 4)
        {
            if (!_wcsicmp(Value, L"enabled"))
                Settings[3] = RouterDiscoveryEnabled;
            else if (!_wcsicmp(Value, L"disabled"))
                Settings[3] = RouterDiscoveryDisabled;
            else if (!_wcsicmp(Value, L"dhcp"))
                Settings[3] = RouterDiscoveryDhcp;
            else
            {
                PrintMessageFromModule(hDllInstance, IDS_ERROR_BAD_VALUE, Value, Tags[Tag].pwszTag);
                Error = ERROR_SUPPRESS_OUTPUT;
            }
            Present[3] = TRUE;
        }
        else if (Tag >= 8 && Tag <= 15)
        {
            if (!_wcsicmp(Value, L"enabled"))
                Settings[Tag - 1] = TRUE;
            else if (!_wcsicmp(Value, L"disabled"))
                Settings[Tag - 1] = FALSE;
            else
            {
                PrintMessageFromModule(hDllInstance, IDS_ERROR_BAD_VALUE, Value, Tags[Tag].pwszTag);
                Error = ERROR_SUPPRESS_OUTPUT;
            }
            Present[Tag - 1] = TRUE;
        }
        else if (Tag == 16)
        {
            if (!Ipv6ParseStore(Value, &Persistent))
            {
                PrintMessageFromModule(hDllInstance, IDS_ERROR_BAD_VALUE, Value, Tags[Tag].pwszTag);
                Error = ERROR_SUPPRESS_OUTPUT;
            }
        }
        else if (Tag >= 1 && Tag <= 7)
        {
            Settings[Tag - 1] = wcstoul(Value, &End, 10);
            Present[Tag - 1] = TRUE;
            if (!*Value || *End)
            {
                PrintMessageFromModule(hDllInstance, IDS_ERROR_BAD_VALUE, Value, Tags[Tag].pwszTag);
                Error = ERROR_SUPPRESS_OUTPUT;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, pTagType);
    if (Error != ERROR_SUCCESS)
        return Error;

    if (Present[0])
    {
        Row.UseAutomaticMetric = FALSE;
        Row.Metric = Settings[0];
    }
    if (Present[1])
        Row.NlMtu = Settings[1];
    if (Present[2])
        Row.SitePrefixLength = Settings[2];
    if (Present[3])
        Row.RouterDiscoveryBehavior = (NL_ROUTER_DISCOVERY_BEHAVIOR)Settings[3];
    if (Present[4])
        Row.DadTransmits = Settings[4];
    if (Present[5])
        Row.BaseReachableTime = Settings[5];
    if (Present[6])
        Row.RetransmitTime = Settings[6];
    if (Present[7])
        Row.ForwardingEnabled = (BOOLEAN)Settings[7];
    if (Present[8])
        Row.AdvertisingEnabled = (BOOLEAN)Settings[8];
    if (Present[9])
        Row.ManagedAddressConfigurationSupported = (BOOLEAN)Settings[9];
    if (Present[10])
        Row.OtherStatefulConfigurationSupported = (BOOLEAN)Settings[10];
    if (Present[11])
        Row.WeakHostSend = (BOOLEAN)Settings[11];
    if (Present[12])
        Row.WeakHostReceive = (BOOLEAN)Settings[12];
    if (Present[13])
        Row.DisableDefaultRoutes = (BOOLEAN)Settings[13];
    if (Present[14])
        Row.AdvertiseDefaultRoute = (BOOLEAN)Settings[14];

    Error = SetIpInterfaceEntry(&Row);
    if (Error != ERROR_SUCCESS)
        return Error;
    if (Persistent)
    {
        for (i = 0; i < ARRAYSIZE(Values); i++)
        {
            if (Present[i])
                Ipv6PersistValue(Row.InterfaceIndex, Values[i], Settings[i]);
        }
    }
    PrintMessageFromModule(hDllInstance, IDS_IPV6_OK);
    return ERROR_SUCCESS;
}

static
DWORD
Ipv6OpenInterfaceKey(NET_IFINDEX Index, REGSAM Access, PHKEY Key)
{
    WCHAR Path[MAX_PATH], GuidText[64];
    NET_LUID Luid;
    GUID Guid;
    DWORD Error;

    Error = ConvertInterfaceIndexToLuid(Index, &Luid);
    if (Error == ERROR_SUCCESS)
        Error = ConvertInterfaceLuidToGuid(&Luid, &Guid);
    if (Error != ERROR_SUCCESS)
        return Error;
    StringFromGUID2(&Guid, GuidText, ARRAYSIZE(GuidText));
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\%s",
                     GuidText);
    return RegCreateKeyExW(HKEY_LOCAL_MACHINE, Path, 0, NULL, 0, Access, NULL, Key, NULL);
}

static
DWORD
Ipv6DnsServers(LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount, BOOL bAdd)
{
    TAG_TYPE Tags[] = {{L"interface", NS_REQ_PRESENT, FALSE},
                       {L"address", NS_REQ_PRESENT, FALSE},
                       {L"index", NS_REQ_ZERO, FALSE}};
    WCHAR Current[1024] = L"", Updated[1024] = L"", Text[INET6_ADDRSTRLEN];
    PWSTR Context = NULL, Token;
    NET_IFINDEX Index = 0;
    IN6_ADDR Address;
    PDWORD pTagType;
    DWORD i, Error, Size = sizeof(Current) - sizeof(WCHAR), Position = (DWORD)-1, Count = 0;
    BOOL bAll = FALSE;
    HKEY Key;

    Error = Ipv6MatchTags(argv, dwCurrentIndex, dwArgCount, Tags, ARRAYSIZE(Tags), &pTagType);
    if (Error != ERROR_SUCCESS)
        return Error;

    for (i = 0; i < dwArgCount - dwCurrentIndex && Error == ERROR_SUCCESS; i++)
    {
        PCWSTR Value = argv[dwCurrentIndex + i];

        switch (pTagType[i])
        {
            case 0:
                if (Ipv6ResolveInterface(Value, &Index) != ERROR_SUCCESS)
                {
                    PrintMessageFromModule(hDllInstance, IDS_ERROR_INVALID_INTERFACE, Value);
                    Error = ERROR_SUPPRESS_OUTPUT;
                }
                break;
            case 1:
                if (!bAdd && !_wcsicmp(Value, L"all"))
                {
                    bAll = TRUE;
                }
                else if (!Ipv6ParseAddress(Value, &Address, NULL, 128))
                {
                    PrintMessageFromModule(hDllInstance, IDS_ERROR_BAD_VALUE, Value, Tags[1].pwszTag);
                    Error = ERROR_SUPPRESS_OUTPUT;
                }
                break;
            case 2:
                Position = wcstoul(Value, NULL, 10);
                break;
        }
    }
    HeapFree(GetProcessHeap(), 0, pTagType);
    if (Error != ERROR_SUCCESS)
        return Error;

    Error = Ipv6OpenInterfaceKey(Index, KEY_READ | KEY_WRITE, &Key);
    if (Error != ERROR_SUCCESS)
        return Error;
    if (RegQueryValueExW(Key, L"NameServer", NULL, NULL, (PBYTE)Current, &Size) != ERROR_SUCCESS)
        Current[0] = UNICODE_NULL;

    if (!bAll)
        RtlIpv6AddressToStringW(&Address, Text);
    for (Token = wcstok_s(Current, L", ", &Context); Token; Token = wcstok_s(NULL, L", ", &Context))
    {
        if (bAll || !_wcsicmp(Token, Text))
            continue;
        if (bAdd && Count + 1 == Position)
        {
            StringCchCatW(Updated, ARRAYSIZE(Updated), Updated[0] ? L"," : L"");
            StringCchCatW(Updated, ARRAYSIZE(Updated), Text);
            Count++;
        }
        StringCchCatW(Updated, ARRAYSIZE(Updated), Updated[0] ? L"," : L"");
        StringCchCatW(Updated, ARRAYSIZE(Updated), Token);
        Count++;
    }
    if (bAdd && (Position == (DWORD)-1 || Position > Count))
    {
        StringCchCatW(Updated, ARRAYSIZE(Updated), Updated[0] ? L"," : L"");
        StringCchCatW(Updated, ARRAYSIZE(Updated), Text);
    }

    Error = RegSetValueExW(Key, L"NameServer", 0, REG_SZ, (PBYTE)Updated, (DWORD)(wcslen(Updated) + 1) * sizeof(WCHAR));
    RegCloseKey(Key);
    return Error;
}

static
DWORD
WINAPI
Ipv6AddDnsServers(LPCWSTR pwszMachine, LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount,
                  DWORD dwFlags, LPCVOID pvData, BOOL *pbDone)
{
    return Ipv6DnsServers(argv, dwCurrentIndex, dwArgCount, TRUE);
}

static
DWORD
WINAPI
Ipv6DeleteDnsServers(LPCWSTR pwszMachine, LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount,
                     DWORD dwFlags, LPCVOID pvData, BOOL *pbDone)
{
    return Ipv6DnsServers(argv, dwCurrentIndex, dwArgCount, FALSE);
}

static
int __cdecl
Ipv6CompareInterfaces(const void *Left, const void *Right)
{
    const MIB_IPINTERFACE_ROW *A = Left, *B = Right;

    return A->InterfaceIndex < B->InterfaceIndex ? -1 : A->InterfaceIndex > B->InterfaceIndex;
}

static
PMIB_IPINTERFACE_TABLE
Ipv6GetInterfaces(VOID)
{
    PMIB_IPINTERFACE_TABLE Table = NULL;

    if (GetIpInterfaceTable(AF_INET6, &Table) != ERROR_SUCCESS)
        return NULL;
    qsort(Table->Table, Table->NumEntries, sizeof(Table->Table[0]), Ipv6CompareInterfaces);
    return Table;
}

static
DWORD
WINAPI
Ipv6ShowAddresses(LPCWSTR pwszMachine, LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount,
                  DWORD dwFlags, LPCVOID pvData, BOOL *pbDone)
{
    PMIB_IPINTERFACE_TABLE Interfaces;
    PMIB_UNICASTIPADDRESS_TABLE Addresses = NULL;
    PIP_ADAPTER_ADDRESSES pList;
    NET_IFINDEX Filter = 0;
    WCHAR Name[256], Valid[32], Preferred[32], Text[INET6_ADDRSTRLEN + 16], Line[512];
    ULONG i, j;

    if (dwArgCount - dwCurrentIndex > 1)
        return ERROR_SHOW_USAGE;
    if (dwArgCount - dwCurrentIndex == 1)
    {
        PWSTR Value = argv[dwCurrentIndex];

        if (!_wcsnicmp(Value, L"interface=", 10))
            Value += 10;
        if (Ipv6ResolveInterface(Value, &Filter) != ERROR_SUCCESS)
        {
            PrintMessageFromModule(hDllInstance, IDS_ERROR_INVALID_INTERFACE, Value);
            return ERROR_SUPPRESS_OUTPUT;
        }
    }

    Interfaces = Ipv6GetInterfaces();
    if (!Interfaces || GetUnicastIpAddressTable(AF_INET6, &Addresses) != ERROR_SUCCESS)
    {
        if (Interfaces)
            FreeMibTable(Interfaces);
        return ERROR_SUPPRESS_OUTPUT;
    }
    pList = Ipv6GetAdapters();

    for (i = 0; i < Interfaces->NumEntries; i++)
    {
        NET_IFINDEX Index = Interfaces->Table[i].InterfaceIndex;

        if (Filter && Index != Filter)
            continue;
        Ipv6InterfaceName(pList, Index, Name, ARRAYSIZE(Name));
        PrintMessageFromModule(hDllInstance, IDS_IPV6_ADDRESS_HEADER, Index, Name);
        for (j = 0; j < Addresses->NumEntries; j++)
        {
            PMIB_UNICASTIPADDRESS_ROW Row = &Addresses->Table[j];
            PCWSTR Type, State;

            if (Row->InterfaceIndex != Index)
                continue;
            if (Row->PrefixOrigin == IpPrefixOriginManual)
                Type = L"Manual";
            else if (Row->PrefixOrigin == IpPrefixOriginDhcp)
                Type = L"Dhcp";
            else if (Row->PrefixOrigin == IpPrefixOriginRouterAdvertisement)
                Type = (Row->SuffixOrigin == IpSuffixOriginRandom && Row->ValidLifetime != 0xFFFFFFFF) ? L"Temporary" : L"Public";
            else
                Type = L"Other";
            switch (Row->DadState)
            {
                case IpDadStateTentative: State = L"Tentative"; break;
                case IpDadStateDuplicate: State = L"Duplicate"; break;
                case IpDadStateDeprecated: State = L"Deprecated"; break;
                case IpDadStateInvalid: State = L"Invalid"; break;
                default: State = L"Preferred"; break;
            }
            Ipv6FormatLifetime(Row->ValidLifetime, Valid, ARRAYSIZE(Valid));
            Ipv6FormatLifetime(Row->PreferredLifetime, Preferred, ARRAYSIZE(Preferred));
            RtlIpv6AddressToStringW(&Row->Address.Ipv6.sin6_addr, Text);
            if (IN6_IS_ADDR_LINKLOCAL(&Row->Address.Ipv6.sin6_addr))
            {
                WCHAR Scope[16];

                StringCchPrintfW(Scope, ARRAYSIZE(Scope), L"%%%lu", Index);
                StringCchCatW(Text, ARRAYSIZE(Text), Scope);
            }
            StringCchPrintfW(Line, ARRAYSIZE(Line), L"%-10s %-11s %10s %10s %s\n", Type, State, Valid, Preferred, Text);
            PrintMessage(L"%s", Line);
        }
    }
    PrintMessage(L"\n");

    if (pList)
        HeapFree(GetProcessHeap(), 0, pList);
    FreeMibTable(Addresses);
    FreeMibTable(Interfaces);
    return ERROR_SUCCESS;
}

static
DWORD
WINAPI
Ipv6ShowRoute(LPCWSTR pwszMachine, LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount,
              DWORD dwFlags, LPCVOID pvData, BOOL *pbDone)
{
    PMIB_IPFORWARD_TABLE2 Table = NULL;
    PIP_ADAPTER_ADDRESSES pList;
    WCHAR Prefix[INET6_ADDRSTRLEN + 8], Gateway[256], Line[512];
    ULONG i;

    if (GetIpForwardTable2(AF_INET6, &Table) != ERROR_SUCCESS)
        return ERROR_SUPPRESS_OUTPUT;
    pList = Ipv6GetAdapters();

    PrintMessageFromModule(hDllInstance, IDS_IPV6_ROUTE_HEADER);
    for (i = 0; i < Table->NumEntries; i++)
    {
        PMIB_IPFORWARD_ROW2 Row = &Table->Table[i];
        PCWSTR Type;

        RtlIpv6AddressToStringW(&Row->DestinationPrefix.Prefix.Ipv6.sin6_addr, Prefix);
        StringCchPrintfW(Prefix + wcslen(Prefix), ARRAYSIZE(Prefix) - wcslen(Prefix), L"/%u",
                         Row->DestinationPrefix.PrefixLength);
        if (IN6_IS_ADDR_UNSPECIFIED(&Row->NextHop.Ipv6.sin6_addr))
            Ipv6InterfaceName(pList, Row->InterfaceIndex, Gateway, ARRAYSIZE(Gateway));
        else
            RtlIpv6AddressToStringW(&Row->NextHop.Ipv6.sin6_addr, Gateway);
        if (Row->Origin == NlroRouterAdvertisement)
            Type = L"Autoconf";
        else if (Row->Protocol == MIB_IPPROTO_NETMGMT)
            Type = L"Manual";
        else
            Type = L"System";
        StringCchPrintfW(Line, ARRAYSIZE(Line), L"%-7s  %-8s  %-3lu  %-24s  %3lu  %s\n",
                         Row->Publish ? L"Yes" : L"No", Type, Row->Metric, Prefix, Row->InterfaceIndex, Gateway);
        PrintMessage(L"%s", Line);
    }
    PrintMessage(L"\n");

    if (pList)
        HeapFree(GetProcessHeap(), 0, pList);
    FreeMibTable(Table);
    return ERROR_SUCCESS;
}

static
DWORD
WINAPI
Ipv6ShowInterfaces(LPCWSTR pwszMachine, LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount,
                   DWORD dwFlags, LPCVOID pvData, BOOL *pbDone)
{
    PMIB_IPINTERFACE_TABLE Interfaces = Ipv6GetInterfaces();
    PIP_ADAPTER_ADDRESSES pList;
    WCHAR Name[256], Line[512];
    ULONG i;

    if (!Interfaces)
        return ERROR_SUPPRESS_OUTPUT;
    pList = Ipv6GetAdapters();

    PrintMessageFromModule(hDllInstance, IDS_IPV6_INTERFACE_HEADER);
    for (i = 0; i < Interfaces->NumEntries; i++)
    {
        PMIB_IPINTERFACE_ROW Row = &Interfaces->Table[i];

        Ipv6InterfaceName(pList, Row->InterfaceIndex, Name, ARRAYSIZE(Name));
        StringCchPrintfW(Line, ARRAYSIZE(Line), L"%3lu  %10lu  %10lu  %-12s  %s\n", Row->InterfaceIndex, Row->Metric,
                         Row->NlMtu, Row->Connected ? L"connected" : L"disconnected", Name);
        PrintMessage(L"%s", Line);
    }
    PrintMessage(L"\n");

    if (pList)
        HeapFree(GetProcessHeap(), 0, pList);
    FreeMibTable(Interfaces);
    return ERROR_SUCCESS;
}

static
DWORD
WINAPI
Ipv6ShowNeighbors(LPCWSTR pwszMachine, LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount,
                  DWORD dwFlags, LPCVOID pvData, BOOL *pbDone)
{
    PMIB_IPINTERFACE_TABLE Interfaces;
    PMIB_IPNET_TABLE2 Neighbors = NULL;
    PIP_ADAPTER_ADDRESSES pList;
    WCHAR Name[256], Text[INET6_ADDRSTRLEN], Physical[64], Line[512];
    NET_IFINDEX Filter = 0;
    ULONG i, j;

    if (dwArgCount > dwCurrentIndex)
    {
        PCWSTR Value = argv[dwCurrentIndex];

        if (!_wcsnicmp(Value, L"interface=", 10))
            Value += 10;
        if (Ipv6ResolveInterface(Value, &Filter) != ERROR_SUCCESS)
        {
            PrintMessageFromModule(hDllInstance, IDS_ERROR_INVALID_INTERFACE, Value);
            return ERROR_SUPPRESS_OUTPUT;
        }
    }

    Interfaces = Ipv6GetInterfaces();
    if (!Interfaces || GetIpNetTable2(AF_INET6, &Neighbors) != ERROR_SUCCESS)
    {
        if (Interfaces)
            FreeMibTable(Interfaces);
        return ERROR_SUPPRESS_OUTPUT;
    }
    pList = Ipv6GetAdapters();

    for (i = 0; i < Interfaces->NumEntries; i++)
    {
        NET_IFINDEX Index = Interfaces->Table[i].InterfaceIndex;

        if (Filter && Index != Filter)
            continue;
        Ipv6InterfaceName(pList, Index, Name, ARRAYSIZE(Name));
        PrintMessageFromModule(hDllInstance, IDS_IPV6_NEIGHBOR_HEADER, Index, Name);
        for (j = 0; j < Neighbors->NumEntries; j++)
        {
            PMIB_IPNET_ROW2 Row = &Neighbors->Table[j];
            PCWSTR State;

            if (Row->InterfaceIndex != Index)
                continue;
            switch (Row->State)
            {
                case NlnsIncomplete: State = L"Incomplete"; break;
                case NlnsProbe: State = L"Probe"; break;
                case NlnsDelay: State = L"Delay"; break;
                case NlnsStale: State = L"Stale"; break;
                case NlnsReachable: State = L"Reachable"; break;
                case NlnsPermanent: State = L"Permanent"; break;
                default: State = L"Unreachable"; break;
            }
            RtlIpv6AddressToStringW(&Row->Address.Ipv6.sin6_addr, Text);
            Physical[0] = UNICODE_NULL;
            if (Row->State == NlnsUnreachable)
                StringCchCopyW(Physical, ARRAYSIZE(Physical), L"Unreachable");
            else
                Ipv6FormatMac(Row->PhysicalAddress, Row->PhysicalAddressLength, Physical, ARRAYSIZE(Physical));
            StringCchPrintfW(Line, ARRAYSIZE(Line), L"%-44s  %-17s  %s \n", Text, Physical, State);
            PrintMessage(L"%s", Line);
        }
    }
    PrintMessage(L"\n");

    if (pList)
        HeapFree(GetProcessHeap(), 0, pList);
    FreeMibTable(Neighbors);
    FreeMibTable(Interfaces);
    return ERROR_SUCCESS;
}

static
DWORD
WINAPI
Ipv6ShowDnsServers(LPCWSTR pwszMachine, LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount,
                   DWORD dwFlags, LPCVOID pvData, BOOL *pbDone)
{
    PIP_ADAPTER_ADDRESSES pList = Ipv6GetAdapters(), pAdapter;
    WCHAR Name[256], Text[INET6_ADDRSTRLEN + 16], Static[1024];
    DWORD Size;
    HKEY Key;

    for (pAdapter = pList; pAdapter; pAdapter = pAdapter->Next)
    {
        PIP_ADAPTER_DNS_SERVER_ADDRESS pDns;
        BOOL bFirst = TRUE, bStatic = FALSE;

        if (!pAdapter->Ipv6IfIndex)
            continue;
        Ipv6InterfaceName(pList, pAdapter->Ipv6IfIndex, Name, ARRAYSIZE(Name));
        PrintMessageFromModule(hDllInstance, IDS_IPV6_DNS_HEADER, Name);

        Static[0] = UNICODE_NULL;
        Size = sizeof(Static) - sizeof(WCHAR);
        if (Ipv6OpenInterfaceKey(pAdapter->Ipv6IfIndex, KEY_READ, &Key) == ERROR_SUCCESS)
        {
            if (RegQueryValueExW(Key, L"NameServer", NULL, NULL, (PBYTE)Static, &Size) != ERROR_SUCCESS)
                Static[0] = UNICODE_NULL;
            RegCloseKey(Key);
        }
        bStatic = Static[0] != UNICODE_NULL;

        for (pDns = pAdapter->FirstDnsServerAddress; pDns; pDns = pDns->Next)
        {
            const SOCKADDR_IN6 *pAddress = (const SOCKADDR_IN6 *)pDns->Address.lpSockaddr;

            if (pAddress->sin6_family != AF_INET6)
                continue;
            RtlIpv6AddressToStringW(&pAddress->sin6_addr, Text);
            if (pAddress->sin6_scope_id)
                StringCchPrintfW(Text + wcslen(Text), ARRAYSIZE(Text) - wcslen(Text), L"%%%lu", pAddress->sin6_scope_id);
            if (bFirst)
                PrintMessageFromModule(hDllInstance, bStatic ? IDS_IPV6_DNS_STATIC : IDS_IPV6_DNS_DHCP, Text);
            else
                PrintMessageFromModule(hDllInstance, IDS_IPV6_DNS_NEXT, Text);
            bFirst = FALSE;
        }
        if (bFirst)
            PrintMessageFromModule(hDllInstance, IDS_IPV6_DNS_DHCP, L"None");
        PrintMessageFromModule(hDllInstance, IDS_IPV6_DNS_SUFFIX);
    }

    if (pList)
        HeapFree(GetProcessHeap(), 0, pList);
    return ERROR_SUCCESS;
}

static
DWORD
WINAPI
Ipv6ShowPrefixPolicies(LPCWSTR pwszMachine, LPWSTR *argv, DWORD dwCurrentIndex, DWORD dwArgCount,
                       DWORD dwFlags, LPCVOID pvData, BOOL *pbDone)
{
    static const struct
    {
        ULONG Precedence;
        ULONG Label;
        PCWSTR Prefix;
    } Policies[] =
    {
        {50, 0, L"::1/128"},
        {40, 1, L"::/0"},
        {35, 4, L"::ffff:0:0/96"},
        {30, 2, L"2002::/16"},
        {5, 5, L"2001::/32"},
        {3, 13, L"fc00::/7"},
        {1, 11, L"fec0::/10"},
        {1, 12, L"3ffe::/16"},
        {1, 3, L"::/96"},
    };
    WCHAR Line[128];
    ULONG i;

    PrintMessageFromModule(hDllInstance, IDS_IPV6_POLICY_HEADER);
    for (i = 0; i < ARRAYSIZE(Policies); i++)
    {
        StringCchPrintfW(Line, ARRAYSIZE(Line), L"%10lu  %5lu  %s\n", Policies[i].Precedence, Policies[i].Label,
                         Policies[i].Prefix);
        PrintMessage(L"%s", Line);
    }
    PrintMessage(L"\n");
    return ERROR_SUCCESS;
}

static
DWORD
WINAPI
Ipv6Start(
    _In_ const GUID *pguidParent,
    _In_ DWORD dwVersion)
{
    NS_CONTEXT_ATTRIBUTES ContextAttributes;

    ZeroMemory(&ContextAttributes, sizeof(ContextAttributes));
    ContextAttributes.dwVersion = 1;
    ContextAttributes.pwszContext = L"ipv6";
    ContextAttributes.guidHelper = GUID_IFMON_IPV6;
    ContextAttributes.ulNumGroups = ARRAYSIZE(Ipv6Groups);
    ContextAttributes.pCmdGroups = Ipv6Groups;

    RegisterContext(&ContextAttributes);
    return ERROR_SUCCESS;
}

DWORD
WINAPI
RegisterIpv6Helper(VOID)
{
    NS_HELPER_ATTRIBUTES HelperAttributes;
    GUID guidParent = GUID_IFMON_INTERFACE;

    ZeroMemory(&HelperAttributes, sizeof(HelperAttributes));
    HelperAttributes.dwVersion = 1;
    HelperAttributes.guidHelper = GUID_IFMON_IPV6;
    HelperAttributes.pfnStart = Ipv6Start;
    HelperAttributes.pfnStop = NULL;
    RegisterHelper(&guidParent, &HelperAttributes);

    return ERROR_SUCCESS;
}
