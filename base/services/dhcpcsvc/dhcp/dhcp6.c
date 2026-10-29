/*
 * PROJECT:     OpenNT DHCP Client Service
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     DHCPv6 client (RFC 8415): stateless configuration and IA_NA addresses
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193@gmail.com>
 */

#include <rosdhcp.h>

#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>
#include <ws2tcpip.h>
#include <netioapi.h>
#include <tcpioctl.h>
#include <tcpip_undoc.h>

#define DHCP6_CLIENT_PORT 546
#define DHCP6_SERVER_PORT 547
#define DHCP6_MAX_INTERFACES 16
#define DHCP6_MAX_ADDRESSES 4
#define DHCP6_MAX_DNS 8
#define DHCP6_MAX_DUID 130

#define DHCP6_SOLICIT 1
#define DHCP6_ADVERTISE 2
#define DHCP6_REQUEST 3
#define DHCP6_RENEW 5
#define DHCP6_REBIND 6
#define DHCP6_REPLY 7
#define DHCP6_RELEASE 8
#define DHCP6_INFORMATION_REQUEST 11
#define DHCP6_RENEW_TIMEOUT 127000
#define DHCP6_PERSISTENT_RETRIES 10

#define DHCP6_OPT_CLIENTID 1
#define DHCP6_OPT_SERVERID 2
#define DHCP6_OPT_IA_NA 3
#define DHCP6_OPT_IAADDR 5
#define DHCP6_OPT_ORO 6
#define DHCP6_OPT_PREFERENCE 7
#define DHCP6_OPT_ELAPSED_TIME 8
#define DHCP6_OPT_STATUS_CODE 13
#define DHCP6_OPT_DNS_SERVERS 23
#define DHCP6_OPT_DOMAIN_LIST 24
#define DHCP6_OPT_INFORMATION_REFRESH_TIME 32

typedef enum _DHCP6_STATE
{
    Dhcp6Idle,
    Dhcp6Informing,
    Dhcp6Informed,
    Dhcp6Soliciting,
    Dhcp6Requesting,
    Dhcp6Bound,
    Dhcp6Renewing,
    Dhcp6Rebinding
} DHCP6_STATE;

typedef struct _DHCP6_ADDRESS
{
    IN6_ADDR Address;
    ULONG Preferred;
    ULONG Valid;
} DHCP6_ADDRESS, *PDHCP6_ADDRESS;

typedef struct _DHCP6_INTERFACE
{
    NET_IFINDEX Index;
    BOOL Present;
    DHCP6_STATE State;
    ULONG Iaid;
    UCHAR Xid[3];
    ULONGLONG Started;
    ULONGLONG NextSend;
    ULONGLONG Deadline;
    ULONG Timeout;
    ULONG MaxTimeout;
    ULONG Retries;
    UCHAR ServerId[DHCP6_MAX_DUID];
    ULONG ServerIdLength;
    ULONG T1;
    ULONG T2;
    ULONGLONG Bound;
    DHCP6_ADDRESS Addresses[DHCP6_MAX_ADDRESSES];
    ULONG AddressCount;
    ULONG Completed;
    BOOL Released;
    BOOL Forced;
} DHCP6_INTERFACE, *PDHCP6_INTERFACE;

static DHCP6_INTERFACE Dhcp6Interfaces[DHCP6_MAX_INTERFACES];
static struct
{
    NET_IFINDEX Index;
    ULONG Attempts;
    BOOL Done;
} Dhcp6Configured[32];
static CRITICAL_SECTION Dhcp6Lock;
static UCHAR Dhcp6Duid[DHCP6_MAX_DUID];
static ULONG Dhcp6DuidLength;
static SOCKET Dhcp6Socket = INVALID_SOCKET;
static const WCHAR Dhcp6ParametersKey[] = L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters";

static
ULONGLONG
Dhcp6Now(VOID)
{
    return GetTickCount64();
}

static
VOID
Dhcp6NewXid(PDHCP6_INTERFACE If)
{
    ULONG Value = (ULONG)(Dhcp6Now() * 2654435761ULL) ^ If->Index ^ GetCurrentProcessId();

    If->Xid[0] = (UCHAR)(Value >> 16);
    If->Xid[1] = (UCHAR)(Value >> 8);
    If->Xid[2] = (UCHAR)Value;
}

static
BOOL
Dhcp6OpenInterfaceKey(NET_IFINDEX Index, REGSAM Access, PHKEY Key)
{
    WCHAR Path[MAX_PATH], GuidText[64];
    NET_LUID Luid;
    GUID Guid;

    if (ConvertInterfaceIndexToLuid(Index, &Luid) != NO_ERROR ||
        ConvertInterfaceLuidToGuid(&Luid, &Guid) != NO_ERROR)
        return FALSE;
    _snwprintf(GuidText, ARRAYSIZE(GuidText), L"{%08lX-%04hX-%04hX-%02X%02X-%02X%02X%02X%02X%02X%02X}",
               Guid.Data1, Guid.Data2, Guid.Data3, Guid.Data4[0], Guid.Data4[1], Guid.Data4[2],
               Guid.Data4[3], Guid.Data4[4], Guid.Data4[5], Guid.Data4[6], Guid.Data4[7]);
    _snwprintf(Path, ARRAYSIZE(Path), L"%s\\Interfaces\\%s", Dhcp6ParametersKey, GuidText);
    return RegCreateKeyExW(HKEY_LOCAL_MACHINE, Path, 0, NULL, 0, Access, NULL, Key, NULL) == ERROR_SUCCESS;
}

static
BOOL
Dhcp6GetMac(NET_IFINDEX Index, PUCHAR Mac)
{
    MIB_IF_ROW2 Row;

    RtlZeroMemory(&Row, sizeof(Row));
    Row.InterfaceIndex = Index;
    if (GetIfEntry2(&Row) != NO_ERROR || Row.PhysicalAddressLength != 6)
        return FALSE;
    RtlCopyMemory(Mac, Row.PhysicalAddress, 6);
    return TRUE;
}

static
VOID
Dhcp6LoadDuid(NET_IFINDEX Index)
{
    DWORD Size = sizeof(Dhcp6Duid), Type;
    UCHAR Mac[6];
    ULONGLONG Seconds;
    FILETIME Now;
    HKEY Key;

    if (Dhcp6DuidLength)
        return;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, Dhcp6ParametersKey, 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &Key, NULL) != ERROR_SUCCESS)
        return;
    if (RegQueryValueExW(Key, L"Dhcpv6DUID", NULL, &Type, Dhcp6Duid, &Size) == ERROR_SUCCESS && Type == REG_BINARY && Size >= 4)
    {
        Dhcp6DuidLength = Size;
    }
    else if (Dhcp6GetMac(Index, Mac))
    {
        GetSystemTimeAsFileTime(&Now);
        Seconds = (((ULONGLONG)Now.dwHighDateTime << 32) | Now.dwLowDateTime) / 10000000ULL - 12591158400ULL;
        Dhcp6Duid[0] = 0; Dhcp6Duid[1] = 1;
        Dhcp6Duid[2] = 0; Dhcp6Duid[3] = 1;
        Dhcp6Duid[4] = (UCHAR)(Seconds >> 24);
        Dhcp6Duid[5] = (UCHAR)(Seconds >> 16);
        Dhcp6Duid[6] = (UCHAR)(Seconds >> 8);
        Dhcp6Duid[7] = (UCHAR)Seconds;
        RtlCopyMemory(&Dhcp6Duid[8], Mac, 6);
        Dhcp6DuidLength = 14;
        RegSetValueExW(Key, L"Dhcpv6DUID", 0, REG_BINARY, Dhcp6Duid, Dhcp6DuidLength);
    }
    RegCloseKey(Key);
}

static
ULONG
Dhcp6LoadIaid(NET_IFINDEX Index)
{
    DWORD Iaid = 0, Size = sizeof(Iaid), Type;
    UCHAR Mac[6] = {0};
    HKEY Key;

    if (!Dhcp6OpenInterfaceKey(Index, KEY_READ | KEY_WRITE, &Key))
        return Index;
    if (RegQueryValueExW(Key, L"Dhcpv6Iaid", NULL, &Type, (PBYTE)&Iaid, &Size) != ERROR_SUCCESS || Type != REG_DWORD)
    {
        Dhcp6GetMac(Index, Mac);
        Iaid = (Index << 24) | (Mac[0] << 16) | (Mac[1] << 8) | Mac[2];
        RegSetValueExW(Key, L"Dhcpv6Iaid", 0, REG_DWORD, (PBYTE)&Iaid, sizeof(Iaid));
    }
    RegCloseKey(Key);
    return Iaid;
}

static
VOID
Dhcp6StoreDns(NET_IFINDEX Index, const IN6_ADDR *Servers, ULONG Count, PCWSTR Domains)
{
    HKEY Key;

    if (!Dhcp6OpenInterfaceKey(Index, KEY_WRITE, &Key))
        return;
    if (Count)
        RegSetValueExW(Key, L"Dhcpv6DNSServers", 0, REG_BINARY, (const BYTE *)Servers, Count * sizeof(IN6_ADDR));
    else
        RegDeleteValueW(Key, L"Dhcpv6DNSServers");
    if (Domains && Domains[0])
        RegSetValueExW(Key, L"Dhcpv6DomainSearchList", 0, REG_SZ, (const BYTE *)Domains, (DWORD)(wcslen(Domains) + 1) * sizeof(WCHAR));
    else
        RegDeleteValueW(Key, L"Dhcpv6DomainSearchList");
    RegCloseKey(Key);
}

static
VOID
Dhcp6RemoveAddresses(PDHCP6_INTERFACE If)
{
    MIB_UNICASTIPADDRESS_ROW Row;
    ULONG i;

    for (i = 0; i < If->AddressCount; i++)
    {
        InitializeUnicastIpAddressEntry(&Row);
        Row.Address.Ipv6.sin6_family = AF_INET6;
        Row.Address.Ipv6.sin6_addr = If->Addresses[i].Address;
        Row.InterfaceIndex = If->Index;
        DeleteUnicastIpAddressEntry(&Row);
    }
    If->AddressCount = 0;
}

static
VOID
Dhcp6InstallAddresses(PDHCP6_INTERFACE If)
{
    MIB_UNICASTIPADDRESS_ROW Row;
    ULONG i;

    for (i = 0; i < If->AddressCount; i++)
    {
        InitializeUnicastIpAddressEntry(&Row);
        Row.Address.Ipv6.sin6_family = AF_INET6;
        Row.Address.Ipv6.sin6_addr = If->Addresses[i].Address;
        Row.InterfaceIndex = If->Index;
        Row.OnLinkPrefixLength = 128;
        Row.PrefixOrigin = IpPrefixOriginDhcp;
        Row.SuffixOrigin = IpSuffixOriginDhcp;
        Row.ValidLifetime = If->Addresses[i].Valid;
        Row.PreferredLifetime = min(If->Addresses[i].Preferred, If->Addresses[i].Valid);
        if (CreateUnicastIpAddressEntry(&Row) == ERROR_OBJECT_ALREADY_EXISTS)
            SetUnicastIpAddressEntry(&Row);
        DH_DbgPrint(MID_TRACE, ("DHCPv6: address on if %lu, valid %lu preferred %lu\n",
                                If->Index, Row.ValidLifetime, Row.PreferredLifetime));
    }
}

static
INT
Dhcp6PutOption(PUCHAR Packet, INT Offset, INT Capacity, USHORT Code, const VOID *Data, USHORT Length)
{
    if (Offset < 0 || Offset + 4 + Length > Capacity)
        return -1;
    Packet[Offset] = (UCHAR)(Code >> 8);
    Packet[Offset + 1] = (UCHAR)Code;
    Packet[Offset + 2] = (UCHAR)(Length >> 8);
    Packet[Offset + 3] = (UCHAR)Length;
    if (Length)
        RtlCopyMemory(Packet + Offset + 4, Data, Length);
    return Offset + 4 + Length;
}

static
VOID
Dhcp6Send(PDHCP6_INTERFACE If, UCHAR Type)
{
    static const UCHAR Oro[] = {0, DHCP6_OPT_DNS_SERVERS, 0, DHCP6_OPT_DOMAIN_LIST};
    UCHAR Packet[512], IaNa[12 + DHCP6_MAX_ADDRESSES * 28], Elapsed[2];
    SOCKADDR_IN6 Target;
    ULONG Centiseconds = (ULONG)min((Dhcp6Now() - If->Started) / 10, 0xFFFF);
    INT Offset = 4, IaLength = 12;
    ULONG i;

    Packet[0] = Type;
    RtlCopyMemory(&Packet[1], If->Xid, 3);
    Elapsed[0] = (UCHAR)(Centiseconds >> 8);
    Elapsed[1] = (UCHAR)Centiseconds;

    Offset = Dhcp6PutOption(Packet, Offset, sizeof(Packet), DHCP6_OPT_CLIENTID, Dhcp6Duid, (USHORT)Dhcp6DuidLength);
    if ((Type == DHCP6_REQUEST || Type == DHCP6_RENEW || Type == DHCP6_RELEASE) && If->ServerIdLength)
        Offset = Dhcp6PutOption(Packet, Offset, sizeof(Packet), DHCP6_OPT_SERVERID, If->ServerId, (USHORT)If->ServerIdLength);
    Offset = Dhcp6PutOption(Packet, Offset, sizeof(Packet), DHCP6_OPT_ELAPSED_TIME, Elapsed, sizeof(Elapsed));
    Offset = Dhcp6PutOption(Packet, Offset, sizeof(Packet), DHCP6_OPT_ORO, Oro, sizeof(Oro));

    if (Type != DHCP6_INFORMATION_REQUEST)
    {
        RtlZeroMemory(IaNa, sizeof(IaNa));
        IaNa[0] = (UCHAR)(If->Iaid >> 24);
        IaNa[1] = (UCHAR)(If->Iaid >> 16);
        IaNa[2] = (UCHAR)(If->Iaid >> 8);
        IaNa[3] = (UCHAR)If->Iaid;
        for (i = 0; Type != DHCP6_SOLICIT && i < If->AddressCount; i++)
        {
            PUCHAR Option = &IaNa[IaLength];

            Option[0] = 0; Option[1] = DHCP6_OPT_IAADDR;
            Option[2] = 0; Option[3] = 24;
            RtlCopyMemory(&Option[4], &If->Addresses[i].Address, 16);
            IaLength += 28;
        }
        Offset = Dhcp6PutOption(Packet, Offset, sizeof(Packet), DHCP6_OPT_IA_NA, IaNa, (USHORT)IaLength);
    }
    if (Offset < 0)
        return;

    RtlZeroMemory(&Target, sizeof(Target));
    Target.sin6_family = AF_INET6;
    Target.sin6_port = htons(DHCP6_SERVER_PORT);
    Target.sin6_addr.u.Byte[0] = 0xff;
    Target.sin6_addr.u.Byte[1] = 0x02;
    Target.sin6_addr.u.Byte[13] = 0x01;
    Target.sin6_addr.u.Byte[15] = 0x02;
    Target.sin6_scope_id = If->Index;
    sendto(Dhcp6Socket, (PCHAR)Packet, Offset, 0, (SOCKADDR *)&Target, sizeof(Target));
    DH_DbgPrint(MID_TRACE, ("DHCPv6: sent type %u on if %lu\n", Type, If->Index));
}

static
VOID
Dhcp6Start(PDHCP6_INTERFACE If, DHCP6_STATE State, ULONG Timeout, ULONG MaxTimeout, ULONG Duration)
{
    ULONGLONG Now = Dhcp6Now();

    If->State = State;
    If->Started = Now;
    If->NextSend = Now;
    If->Timeout = Timeout;
    If->MaxTimeout = MaxTimeout;
    If->Retries = 0;
    If->Deadline = Duration ? Now + (ULONGLONG)Duration * 1000 : 0;
    Dhcp6NewXid(If);
}

static
INT
Dhcp6ReadName(const UCHAR *Data, INT Length, INT Offset, PWSTR Name, INT Count)
{
    INT Out = 0;

    while (Offset < Length)
    {
        UCHAR Label = Data[Offset++];

        if (!Label)
        {
            Name[Out] = UNICODE_NULL;
            return Offset;
        }
        if (Label > 63 || Offset + Label > Length || Out + Label + 2 >= Count)
            return -1;
        if (Out)
            Name[Out++] = L'.';
        while (Label--)
            Name[Out++] = (WCHAR)Data[Offset++];
    }
    return -1;
}

static
VOID
Dhcp6ParseConfig(PDHCP6_INTERFACE If, const UCHAR *Options, INT Length, PULONG Refresh)
{
    IN6_ADDR Servers[DHCP6_MAX_DNS];
    WCHAR Domains[512] = L"", Name[256];
    ULONG Count = 0;
    INT Offset = 0;

    while (Offset + 4 <= Length)
    {
        USHORT Code = (Options[Offset] << 8) | Options[Offset + 1];
        USHORT Size = (Options[Offset + 2] << 8) | Options[Offset + 3];
        const UCHAR *Data = Options + Offset + 4;

        if (Offset + 4 + Size > Length)
            break;
        if (Code == DHCP6_OPT_DNS_SERVERS)
        {
            INT i;

            for (i = 0; i + 16 <= Size && Count < DHCP6_MAX_DNS; i += 16)
                RtlCopyMemory(&Servers[Count++], Data + i, 16);
        }
        else if (Code == DHCP6_OPT_DOMAIN_LIST)
        {
            INT i = 0;

            while (i < Size && (i = Dhcp6ReadName(Data, Size, i, Name, ARRAYSIZE(Name))) > 0)
            {
                if (Name[0] && wcslen(Domains) + wcslen(Name) + 2 < ARRAYSIZE(Domains))
                {
                    if (Domains[0])
                        wcscat(Domains, L",");
                    wcscat(Domains, Name);
                }
            }
        }
        else if (Code == DHCP6_OPT_INFORMATION_REFRESH_TIME && Size == 4 && Refresh)
        {
            *Refresh = (Data[0] << 24) | (Data[1] << 16) | (Data[2] << 8) | Data[3];
        }
        Offset += 4 + Size;
    }

    Dhcp6StoreDns(If->Index, Servers, Count, Domains);
}

static
USHORT
Dhcp6Status(const UCHAR *Options, INT Length)
{
    INT Offset = 0;

    while (Offset + 4 <= Length)
    {
        USHORT Code = (Options[Offset] << 8) | Options[Offset + 1];
        USHORT Size = (Options[Offset + 2] << 8) | Options[Offset + 3];

        if (Offset + 4 + Size > Length)
            break;
        if (Code == DHCP6_OPT_STATUS_CODE && Size >= 2)
            return (Options[Offset + 4] << 8) | Options[Offset + 5];
        Offset += 4 + Size;
    }
    return 0;
}

static
BOOL
Dhcp6ParseIaNa(PDHCP6_INTERFACE If, const UCHAR *Options, INT Length)
{
    INT Offset = 0;
    BOOL Found = FALSE;

    while (Offset + 4 <= Length)
    {
        USHORT Code = (Options[Offset] << 8) | Options[Offset + 1];
        USHORT Size = (Options[Offset + 2] << 8) | Options[Offset + 3];
        const UCHAR *Data = Options + Offset + 4;

        if (Offset + 4 + Size > Length)
            break;
        if (Code == DHCP6_OPT_IA_NA && Size >= 12 &&
            ((ULONG)Data[0] << 24 | Data[1] << 16 | Data[2] << 8 | Data[3]) == If->Iaid &&
            Dhcp6Status(Data + 12, Size - 12) == 0)
        {
            INT Inner = 12;

            If->T1 = (Data[4] << 24) | (Data[5] << 16) | (Data[6] << 8) | Data[7];
            If->T2 = (Data[8] << 24) | (Data[9] << 16) | (Data[10] << 8) | Data[11];
            If->AddressCount = 0;
            while (Inner + 4 <= Size)
            {
                USHORT InnerCode = (Data[Inner] << 8) | Data[Inner + 1];
                USHORT InnerSize = (Data[Inner + 2] << 8) | Data[Inner + 3];
                const UCHAR *Address = Data + Inner + 4;

                if (Inner + 4 + InnerSize > Size)
                    break;
                if (InnerCode == DHCP6_OPT_IAADDR && InnerSize >= 24 && If->AddressCount < DHCP6_MAX_ADDRESSES)
                {
                    PDHCP6_ADDRESS Entry = &If->Addresses[If->AddressCount];

                    RtlCopyMemory(&Entry->Address, Address, 16);
                    Entry->Preferred = (Address[16] << 24) | (Address[17] << 16) | (Address[18] << 8) | Address[19];
                    Entry->Valid = (Address[20] << 24) | (Address[21] << 16) | (Address[22] << 8) | Address[23];
                    if (Entry->Valid && Dhcp6Status(Address + 24, InnerSize - 24) == 0)
                    {
                        If->AddressCount++;
                        Found = TRUE;
                    }
                }
                Inner += 4 + InnerSize;
            }
        }
        Offset += 4 + Size;
    }
    return Found;
}

static
VOID
Dhcp6Receive(VOID)
{
    UCHAR Packet[1500];
    SOCKADDR_IN6 From;
    INT FromLength = sizeof(From), Length, Offset;
    ULONG i;

    Length = recvfrom(Dhcp6Socket, (PCHAR)Packet, sizeof(Packet), 0, (SOCKADDR *)&From, &FromLength);
    if (Length < 4 || (Packet[0] != DHCP6_ADVERTISE && Packet[0] != DHCP6_REPLY))
        return;

    for (i = 0; i < DHCP6_MAX_INTERFACES; i++)
    {
        PDHCP6_INTERFACE If = &Dhcp6Interfaces[i];
        const UCHAR *ServerId = NULL;
        USHORT ServerIdLength = 0;
        BOOL ClientMatch = FALSE;

        if (!If->Present || memcmp(&Packet[1], If->Xid, 3))
            continue;

        for (Offset = 4; Offset + 4 <= Length;)
        {
            USHORT Code = (Packet[Offset] << 8) | Packet[Offset + 1];
            USHORT Size = (Packet[Offset + 2] << 8) | Packet[Offset + 3];

            if (Offset + 4 + Size > Length)
                break;
            if (Code == DHCP6_OPT_CLIENTID && Size == Dhcp6DuidLength && !memcmp(&Packet[Offset + 4], Dhcp6Duid, Size))
                ClientMatch = TRUE;
            else if (Code == DHCP6_OPT_SERVERID && Size <= DHCP6_MAX_DUID)
            {
                ServerId = &Packet[Offset + 4];
                ServerIdLength = Size;
            }
            Offset += 4 + Size;
        }
        if (!ClientMatch || !ServerId)
            return;

        if (If->State == Dhcp6Informing && Packet[0] == DHCP6_REPLY)
        {
            ULONG Refresh = 86400;

            Dhcp6ParseConfig(If, &Packet[4], Length - 4, &Refresh);
            If->State = Dhcp6Informed;
            If->Bound = Dhcp6Now();
            If->T1 = max(Refresh, 600);
            If->Completed++;
            DH_DbgPrint(MID_TRACE, ("DHCPv6: stateless configuration on if %lu\n", If->Index));
        }
        else if (If->State == Dhcp6Soliciting && Packet[0] == DHCP6_ADVERTISE)
        {
            if (Dhcp6Status(&Packet[4], Length - 4) != 0 || !Dhcp6ParseIaNa(If, &Packet[4], Length - 4))
                return;
            RtlCopyMemory(If->ServerId, ServerId, ServerIdLength);
            If->ServerIdLength = ServerIdLength;
            Dhcp6Start(If, Dhcp6Requesting, 1000, 30000, 0);
        }
        else if ((If->State == Dhcp6Requesting || If->State == Dhcp6Renewing || If->State == Dhcp6Rebinding) &&
                 Packet[0] == DHCP6_REPLY)
        {
            if (Dhcp6Status(&Packet[4], Length - 4) != 0 || !Dhcp6ParseIaNa(If, &Packet[4], Length - 4))
            {
                Dhcp6RemoveAddresses(If);
                Dhcp6Start(If, Dhcp6Soliciting, 1000, 3600000, 0);
                return;
            }
            RtlCopyMemory(If->ServerId, ServerId, ServerIdLength);
            If->ServerIdLength = ServerIdLength;
            Dhcp6InstallAddresses(If);
            Dhcp6ParseConfig(If, &Packet[4], Length - 4, NULL);
            if (!If->T1 || If->T1 == 0xFFFFFFFF)
                If->T1 = If->Addresses[0].Preferred / 2;
            if (!If->T2 || If->T2 == 0xFFFFFFFF || If->T2 < If->T1)
                If->T2 = (ULONG)((ULONGLONG)If->Addresses[0].Preferred * 8 / 10);
            If->State = Dhcp6Bound;
            If->Bound = Dhcp6Now();
            If->Completed++;
            DH_DbgPrint(MID_TRACE, ("DHCPv6: bound on if %lu, T1 %lu T2 %lu\n", If->Index, If->T1, If->T2));
        }
        return;
    }
}

static
VOID
Dhcp6Tick(PDHCP6_INTERFACE If)
{
    ULONGLONG Now = Dhcp6Now();
    ULONGLONG Elapsed = (Now - If->Bound) / 1000;

    if (If->Released)
        return;
    switch (If->State)
    {
        case Dhcp6Informed:
            if (Elapsed >= If->T1)
                Dhcp6Start(If, Dhcp6Informing, 1000, 3600000, 0);
            return;

        case Dhcp6Bound:
            if (Elapsed >= If->T2)
                Dhcp6Start(If, Dhcp6Rebinding, 10000, 600000, 0);
            else if (Elapsed >= If->T1)
                Dhcp6Start(If, Dhcp6Renewing, 10000, 600000, 0);
            return;

        case Dhcp6Renewing:
            if (Elapsed >= If->T2)
            {
                Dhcp6Start(If, Dhcp6Rebinding, 10000, 600000, 0);
                return;
            }
            break;

        case Dhcp6Rebinding:
            if (If->AddressCount && Elapsed >= If->Addresses[0].Valid)
            {
                Dhcp6RemoveAddresses(If);
                Dhcp6Start(If, Dhcp6Soliciting, 1000, 3600000, 0);
                return;
            }
            break;

        case Dhcp6Requesting:
            if (If->Retries >= 10)
            {
                Dhcp6Start(If, Dhcp6Soliciting, 1000, 3600000, 0);
                return;
            }
            break;

        case Dhcp6Informing:
        case Dhcp6Soliciting:
            break;

        default:
            return;
    }

    if (Now >= If->NextSend)
    {
        static const UCHAR Types[] = {0, DHCP6_INFORMATION_REQUEST, 0, DHCP6_SOLICIT, DHCP6_REQUEST, 0,
                                      DHCP6_RENEW, DHCP6_REBIND};

        Dhcp6Send(If, Types[If->State]);
        If->NextSend = Now + If->Timeout;
        If->Timeout = min(If->Timeout * 2, If->MaxTimeout);
        If->Retries++;
    }
}

static
BOOL
Dhcp6ApplyPersistentList(HKEY Key, PCWSTR List, NET_IFINDEX Index)
{
    WCHAR Buffer[4096];
    DWORD Size = sizeof(Buffer) - 2 * sizeof(WCHAR), Type;
    PWSTR Entry;
    BOOL Applied = TRUE;

    if (RegQueryValueExW(Key, List, NULL, &Type, (PBYTE)Buffer, &Size) != ERROR_SUCCESS || Type != REG_MULTI_SZ)
        return TRUE;
    Buffer[Size / sizeof(WCHAR)] = UNICODE_NULL;
    Buffer[Size / sizeof(WCHAR) + 1] = UNICODE_NULL;

    for (Entry = Buffer; *Entry; Entry += wcslen(Entry) + 1)
    {
        WCHAR First[64], Second[64];
        ULONG A = 0, B = 0, C = 0;
        PCWSTR End;
        IN6_ADDR Address;
        DWORD Error = ERROR_INVALID_PARAMETER;

        if (swscanf(Entry, L"%63s %63s %lu %lu", First, Second, &B, &C) < 2)
            continue;
        if (!wcscmp(List, L"Addresses"))
        {
            MIB_UNICASTIPADDRESS_ROW Row;

            if (swscanf(Entry, L"%63s %lu %lu %lu", First, &A, &B, &C) != 4 ||
                !NT_SUCCESS(RtlIpv6StringToAddressW(First, &End, &Address)))
                continue;
            InitializeUnicastIpAddressEntry(&Row);
            Row.Address.Ipv6.sin6_family = AF_INET6;
            Row.Address.Ipv6.sin6_addr = Address;
            Row.InterfaceIndex = Index;
            Row.OnLinkPrefixLength = (UINT8)A;
            Row.ValidLifetime = B;
            Row.PreferredLifetime = C;
            Error = CreateUnicastIpAddressEntry(&Row);
        }
        else if (!wcscmp(List, L"Routes"))
        {
            MIB_IPFORWARD_ROW2 Row;
            PWSTR Slash = wcschr(First, L'/');

            if (!Slash)
                continue;
            *Slash = UNICODE_NULL;
            InitializeIpForwardEntry(&Row);
            Row.InterfaceIndex = Index;
            Row.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
            Row.DestinationPrefix.PrefixLength = (UINT8)wcstoul(Slash + 1, NULL, 10);
            Row.NextHop.Ipv6.sin6_family = AF_INET6;
            Row.Metric = B;
            if (!NT_SUCCESS(RtlIpv6StringToAddressW(First, &End, &Row.DestinationPrefix.Prefix.Ipv6.sin6_addr)) ||
                !NT_SUCCESS(RtlIpv6StringToAddressW(Second, &End, &Row.NextHop.Ipv6.sin6_addr)))
                continue;
            Error = CreateIpForwardEntry2(&Row);
        }
        else
        {
            MIB_IPNET_ROW2 Row;
            PWSTR Mac = Second;

            RtlZeroMemory(&Row, sizeof(Row));
            Row.Address.Ipv6.sin6_family = AF_INET6;
            Row.InterfaceIndex = Index;
            if (!NT_SUCCESS(RtlIpv6StringToAddressW(First, &End, &Row.Address.Ipv6.sin6_addr)))
                continue;
            while (*Mac && Row.PhysicalAddressLength < 8)
            {
                Row.PhysicalAddress[Row.PhysicalAddressLength++] = (UCHAR)wcstoul(Mac, &Mac, 16);
                if (*Mac == L'-' || *Mac == L':')
                    Mac++;
            }
            Error = CreateIpNetEntry2(&Row);
        }
        if (Error != ERROR_SUCCESS && Error != ERROR_OBJECT_ALREADY_EXISTS)
            Applied = FALSE;
        DH_DbgPrint(MID_TRACE, ("DHCPv6: persistent %S entry '%S' on if %lu: %lu\n", List, Entry, Index, Error));
    }
    return Applied;
}

static
VOID
Dhcp6ApplyPersistentStore(NET_IFINDEX Index)
{
    static PCWSTR Values[] = {L"Metric", L"Mtu", L"SitePrefixLength", L"RouterDiscovery", L"DadTransmits",
                              L"BaseReachableTime", L"RetransmitTime", L"Forwarding", L"Advertise",
                              L"ManagedAddress", L"OtherStateful", L"WeakHostSend", L"WeakHostReceive",
                              L"IgnoreDefaultRoutes", L"AdvertiseDefaultRoute"};
    MIB_IPINTERFACE_ROW Row;
    HKEY Interface, Key;
    BOOL Changed = FALSE, Applied = TRUE;
    ULONG i, Slot = ARRAYSIZE(Dhcp6Configured);

    for (i = 0; i < ARRAYSIZE(Dhcp6Configured); i++)
    {
        if (Dhcp6Configured[i].Index == Index)
        {
            Slot = i;
            break;
        }
        if (!Dhcp6Configured[i].Index && Slot == ARRAYSIZE(Dhcp6Configured))
            Slot = i;
    }
    if (Slot == ARRAYSIZE(Dhcp6Configured) || Dhcp6Configured[Slot].Done)
        return;
    Dhcp6Configured[Slot].Index = Index;
    if (++Dhcp6Configured[Slot].Attempts >= DHCP6_PERSISTENT_RETRIES)
        Dhcp6Configured[Slot].Done = TRUE;

    if (!Dhcp6OpenInterfaceKey(Index, KEY_READ, &Interface))
        return;
    if (RegOpenKeyExW(Interface, L"PersistentStore", 0, KEY_READ, &Key) != ERROR_SUCCESS)
    {
        RegCloseKey(Interface);
        Dhcp6Configured[Slot].Done = TRUE;
        return;
    }
    RegCloseKey(Interface);

    InitializeIpInterfaceEntry(&Row);
    Row.Family = AF_INET6;
    Row.InterfaceIndex = Index;
    for (i = 0; i < ARRAYSIZE(Values); i++)
    {
        DWORD Value, Size = sizeof(Value), Type;

        if (RegQueryValueExW(Key, Values[i], NULL, &Type, (PBYTE)&Value, &Size) != ERROR_SUCCESS || Type != REG_DWORD)
            continue;
        Changed = TRUE;
        switch (i)
        {
            case 0: Row.UseAutomaticMetric = FALSE; Row.Metric = Value; break;
            case 1: Row.NlMtu = Value; break;
            case 2: Row.SitePrefixLength = Value; break;
            case 3: Row.RouterDiscoveryBehavior = (NL_ROUTER_DISCOVERY_BEHAVIOR)Value; break;
            case 4: Row.DadTransmits = Value; break;
            case 5: Row.BaseReachableTime = Value; break;
            case 6: Row.RetransmitTime = Value; break;
            case 7: Row.ForwardingEnabled = (BOOLEAN)Value; break;
            case 8: Row.AdvertisingEnabled = (BOOLEAN)Value; break;
            case 9: Row.ManagedAddressConfigurationSupported = (BOOLEAN)Value; break;
            case 10: Row.OtherStatefulConfigurationSupported = (BOOLEAN)Value; break;
            case 11: Row.WeakHostSend = (BOOLEAN)Value; break;
            case 12: Row.WeakHostReceive = (BOOLEAN)Value; break;
            case 13: Row.DisableDefaultRoutes = (BOOLEAN)Value; break;
            default: Row.AdvertiseDefaultRoute = (BOOLEAN)Value; break;
        }
    }
    if (Changed && SetIpInterfaceEntry(&Row) != ERROR_SUCCESS)
        Applied = FALSE;

    if (!Dhcp6ApplyPersistentList(Key, L"Addresses", Index))
        Applied = FALSE;
    if (!Dhcp6ApplyPersistentList(Key, L"Routes", Index))
        Applied = FALSE;
    if (!Dhcp6ApplyPersistentList(Key, L"Neighbors", Index))
        Applied = FALSE;
    RegCloseKey(Key);
    if (Applied)
        Dhcp6Configured[Slot].Done = TRUE;
}

static
VOID
Dhcp6Scan(VOID)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\Ip6");
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    PIP6_TABLE_HEADER Header;
    PIP6_INTERFACE_ROW Rows;
    ULONG Size = sizeof(IP6_TABLE_HEADER) + 32 * sizeof(IP6_INTERFACE_ROW), i, j;
    HANDLE File;

    for (i = 0; i < DHCP6_MAX_INTERFACES; i++)
        Dhcp6Interfaces[i].Present = FALSE;

    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (!NT_SUCCESS(NtOpenFile(&File, SYNCHRONIZE, &Attributes, &Iosb, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               FILE_SYNCHRONOUS_IO_NONALERT)))
        return;
    Header = HeapAlloc(GetProcessHeap(), 0, Size);
    if (Header)
    {
        *(PULONG)Header = Ip6TableInterfaces;
        if (NT_SUCCESS(NtDeviceIoControlFile(File, NULL, NULL, NULL, &Iosb, IOCTL_IP6_QUERY_TABLE,
                                             Header, sizeof(ULONG), Header, Size)))
        {
            Rows = (PIP6_INTERFACE_ROW)(Header + 1);
            for (i = 0; i < Header->Count; i++)
            {
                PIP6_INTERFACE_ROW Row = &Rows[i];
                PDHCP6_INTERFACE If = NULL, Free = NULL;
                BOOL Wanted = !Row->Loopback && Row->Connected && Row->RouterAdvertised &&
                              (Row->ManagedAddressConfiguration || Row->OtherStatefulConfiguration);

                if (!Row->Loopback)
                    Dhcp6ApplyPersistentStore(Row->Index);
                for (j = 0; j < DHCP6_MAX_INTERFACES; j++)
                {
                    if (Dhcp6Interfaces[j].Index == Row->Index)
                        If = &Dhcp6Interfaces[j];
                    else if (!Dhcp6Interfaces[j].Index && !Free)
                        Free = &Dhcp6Interfaces[j];
                }
                if (If && If->Forced && !Row->Loopback && Row->Connected)
                    Wanted = TRUE;

                if (!Wanted)
                {
                    if (If)
                    {
                        Dhcp6RemoveAddresses(If);
                        Dhcp6StoreDns(If->Index, NULL, 0, NULL);
                        RtlZeroMemory(If, sizeof(*If));
                    }
                    continue;
                }
                if (!If)
                {
                    if (!Free)
                        continue;
                    If = Free;
                    RtlZeroMemory(If, sizeof(*If));
                    If->Index = Row->Index;
                    Dhcp6LoadDuid(Row->Index);
                    If->Iaid = Dhcp6LoadIaid(Row->Index);
                }
                If->Present = TRUE;
                if (If->Released || If->Forced)
                    continue;

                if (Row->ManagedAddressConfiguration && (If->State == Dhcp6Idle || If->State == Dhcp6Informing ||
                                                         If->State == Dhcp6Informed))
                    Dhcp6Start(If, Dhcp6Soliciting, 1000, 3600000, 0);
                else if (!Row->ManagedAddressConfiguration && If->State == Dhcp6Idle)
                    Dhcp6Start(If, Dhcp6Informing, 1000, 3600000, 0);
            }
        }
        HeapFree(GetProcessHeap(), 0, Header);
    }
    NtClose(File);

    for (i = 0; i < DHCP6_MAX_INTERFACES; i++)
    {
        if (Dhcp6Interfaces[i].Index && !Dhcp6Interfaces[i].Present)
        {
            Dhcp6StoreDns(Dhcp6Interfaces[i].Index, NULL, 0, NULL);
            RtlZeroMemory(&Dhcp6Interfaces[i], sizeof(Dhcp6Interfaces[i]));
        }
    }
}

static
DWORD
WINAPI
Dhcp6Thread(LPVOID Parameter)
{
    HANDLE StopEvent = Parameter;
    SOCKADDR_IN6 Local;
    ULONGLONG NextScan = 0;
    INT On = 1;

    Dhcp6Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (Dhcp6Socket == INVALID_SOCKET)
        return 0;
    setsockopt(Dhcp6Socket, SOL_SOCKET, SO_REUSEADDR, (PCHAR)&On, sizeof(On));
    RtlZeroMemory(&Local, sizeof(Local));
    Local.sin6_family = AF_INET6;
    Local.sin6_port = htons(DHCP6_CLIENT_PORT);
    if (bind(Dhcp6Socket, (SOCKADDR *)&Local, sizeof(Local)) == SOCKET_ERROR)
    {
        closesocket(Dhcp6Socket);
        Dhcp6Socket = INVALID_SOCKET;
        return 0;
    }

    while (WaitForSingleObject(StopEvent, 0) == WAIT_TIMEOUT)
    {
        struct timeval Wait = {0, 250000};
        fd_set Read;
        ULONG i;

        EnterCriticalSection(&Dhcp6Lock);
        if (Dhcp6Now() >= NextScan)
        {
            Dhcp6Scan();
            NextScan = Dhcp6Now() + 2000;
        }
        for (i = 0; i < DHCP6_MAX_INTERFACES; i++)
        {
            if (Dhcp6Interfaces[i].Present)
                Dhcp6Tick(&Dhcp6Interfaces[i]);
        }
        LeaveCriticalSection(&Dhcp6Lock);

        FD_ZERO(&Read);
        FD_SET(Dhcp6Socket, &Read);
        if (select(0, &Read, NULL, NULL, &Wait) > 0)
        {
            EnterCriticalSection(&Dhcp6Lock);
            Dhcp6Receive();
            LeaveCriticalSection(&Dhcp6Lock);
        }
    }

    closesocket(Dhcp6Socket);
    Dhcp6Socket = INVALID_SOCKET;
    return 0;
}

static
NET_IFINDEX
Dhcp6AdapterIndex(PCWSTR AdapterName)
{
    UNICODE_STRING String;
    NET_LUID Luid;
    NET_IFINDEX Index = 0;
    GUID Guid;

    RtlInitUnicodeString(&String, AdapterName);
    if (!NT_SUCCESS(RtlGUIDFromString(&String, &Guid)) || ConvertInterfaceGuidToLuid(&Guid, &Luid) != NO_ERROR ||
        ConvertInterfaceLuidToIndex(&Luid, &Index) != NO_ERROR)
        return 0;
    return Index;
}

static
PDHCP6_INTERFACE
Dhcp6FindInterface(NET_IFINDEX Index, BOOL Create)
{
    PDHCP6_INTERFACE Free = NULL;
    ULONG i;

    for (i = 0; i < DHCP6_MAX_INTERFACES; i++)
    {
        if (Dhcp6Interfaces[i].Index == Index)
            return &Dhcp6Interfaces[i];
        if (!Dhcp6Interfaces[i].Index && !Free)
            Free = &Dhcp6Interfaces[i];
    }
    if (!Create || !Free)
        return NULL;
    RtlZeroMemory(Free, sizeof(*Free));
    Free->Index = Index;
    Dhcp6LoadDuid(Index);
    Free->Iaid = Dhcp6LoadIaid(Index);
    return Free;
}

DWORD
Dhcp6ReleaseAdapter(PCWSTR AdapterName)
{
    NET_IFINDEX Index = Dhcp6AdapterIndex(AdapterName);
    PDHCP6_INTERFACE If;

    if (!Index)
        return ERROR_FILE_NOT_FOUND;
    if (Dhcp6Socket == INVALID_SOCKET)
        return ERROR_NOT_READY;

    EnterCriticalSection(&Dhcp6Lock);
    If = Dhcp6FindInterface(Index, FALSE);
    if (If && If->AddressCount)
    {
        Dhcp6NewXid(If);
        If->Started = Dhcp6Now();
        Dhcp6Send(If, DHCP6_RELEASE);
        Dhcp6RemoveAddresses(If);
        Dhcp6StoreDns(If->Index, NULL, 0, NULL);
    }
    if (If)
    {
        If->State = Dhcp6Idle;
        If->Released = TRUE;
        If->Forced = FALSE;
    }
    LeaveCriticalSection(&Dhcp6Lock);
    return ERROR_SUCCESS;
}

DWORD
Dhcp6RenewAdapter(PCWSTR AdapterName)
{
    NET_IFINDEX Index = Dhcp6AdapterIndex(AdapterName);
    MIB_IPINTERFACE_ROW Row;
    PDHCP6_INTERFACE If;
    ULONGLONG Deadline;
    ULONG Completed;
    BOOL Managed;

    if (!Index)
        return ERROR_FILE_NOT_FOUND;
    if (Dhcp6Socket == INVALID_SOCKET)
        return ERROR_NOT_READY;

    RtlZeroMemory(&Row, sizeof(Row));
    Row.Family = AF_INET6;
    Row.InterfaceIndex = Index;
    if (GetIpInterfaceEntry(&Row) != NO_ERROR)
        return ERROR_FILE_NOT_FOUND;
    Managed = Row.ManagedAddressConfigurationSupported || !Row.OtherStatefulConfigurationSupported;

    EnterCriticalSection(&Dhcp6Lock);
    If = Dhcp6FindInterface(Index, TRUE);
    if (!If)
    {
        LeaveCriticalSection(&Dhcp6Lock);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    If->Present = TRUE;
    If->Released = FALSE;
    If->Forced = TRUE;
    Completed = If->Completed;
    if (If->State == Dhcp6Bound || If->State == Dhcp6Renewing || If->State == Dhcp6Rebinding)
        Dhcp6Start(If, Dhcp6Renewing, 1000, 10000, 0);
    else
        Dhcp6Start(If, Managed ? Dhcp6Soliciting : Dhcp6Informing, 1000, 10000, 0);
    LeaveCriticalSection(&Dhcp6Lock);

    for (Deadline = Dhcp6Now() + DHCP6_RENEW_TIMEOUT; Dhcp6Now() < Deadline; Sleep(250))
    {
        BOOL Done;

        EnterCriticalSection(&Dhcp6Lock);
        If = Dhcp6FindInterface(Index, FALSE);
        Done = !If || If->Completed != Completed;
        LeaveCriticalSection(&Dhcp6Lock);
        if (Done)
            return If ? ERROR_SUCCESS : ERROR_FILE_NOT_FOUND;
    }

    EnterCriticalSection(&Dhcp6Lock);
    If = Dhcp6FindInterface(Index, FALSE);
    if (If)
        If->Forced = FALSE;
    LeaveCriticalSection(&Dhcp6Lock);
    return ERROR_SEM_TIMEOUT;
}

HANDLE
StartDhcp6Client(HANDLE StopEvent)
{
    HANDLE Thread;

    InitializeCriticalSection(&Dhcp6Lock);
    Thread = CreateThread(NULL, 0, Dhcp6Thread, StopEvent, 0, NULL);

    return Thread ? Thread : INVALID_HANDLE_VALUE;
}
