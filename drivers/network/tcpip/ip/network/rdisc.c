/*
 * PROJECT:     OpenNT TCP/IP protocol driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     ICMP router discovery (RFC 1256) for IPv4 interfaces
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193@gmail.com>
 */

#include "precomp.h"

#include <icmp.h>
#include <nldef.h>

#define RDISC_SOLICITATIONS     3
#define RDISC_FIRST_SOLICIT     500
#define RDISC_SOLICIT_INTERVAL  4000
#define RDISC_ALL_ROUTERS       0xE0000002
#define RDISC_NOT_DEFAULT       0x80000000
#define RDISC_TAG               'sDRT'

typedef struct _RDISC_SOLICIT
{
    LIST_ENTRY ListEntry;
    PIP_INTERFACE Interface;
    ULONG Remaining;
    ULONGLONG Next;
    ULONGLONG ListenUntil;
    BOOLEAN Queued;
} RDISC_SOLICIT, *PRDISC_SOLICIT;

#pragma pack(push, 1)
typedef struct _RDISC_ADVERT
{
    UCHAR Type;
    UCHAR Code;
    USHORT Checksum;
    UCHAR Addresses;
    UCHAR EntrySize;
    USHORT Lifetime;
} RDISC_ADVERT, *PRDISC_ADVERT;
#pragma pack(pop)

static LIST_ENTRY RdiscSolicits;
static KSPIN_LOCK RdiscLock;

BOOLEAN RdiscEnabled(PIP_INTERFACE Interface)
{
    return Interface->RouterDiscoveryBehavior == RouterDiscoveryEnabled ||
           (Interface->RouterDiscoveryBehavior == RouterDiscoveryDhcp && Interface->DhcpRouterDiscovery);
}

static PRDISC_SOLICIT RdiscFind(PIP_INTERFACE Interface)
{
    PLIST_ENTRY Entry;

    for (Entry = RdiscSolicits.Flink; Entry != &RdiscSolicits; Entry = Entry->Flink)
    {
        PRDISC_SOLICIT Solicit = CONTAINING_RECORD(Entry, RDISC_SOLICIT, ListEntry);

        if (Solicit->Interface == Interface)
            return Solicit;
    }
    return NULL;
}

static VOID RdiscTransmitSolicitation(PIP_INTERFACE Interface)
{
    IP_PACKET Packet;
    IP_ADDRESS Destination, Source;
    PNEIGHBOR_CACHE_ENTRY NCE;
    PIPv4_HEADER Header;
    PICMP_HEADER Icmp;
    UINT HeaderSize = sizeof(IPv4_HEADER);
    UINT DataSize = sizeof(ICMP_HEADER);
    UINT Contiguous;

    AddrInitIPv4(&Destination, DH2N(RDISC_ALL_ROUTERS));
    if (!GetInterfaceSourceAddress(Interface, &Destination, NULL, &Source))
        return;

    NCE = RouteGetMulticastRoute(&Destination, DH2N(Interface->Index));
    if (!NCE)
        return;

    IPInitializePacket(&Packet, IP_ADDRESS_V4);
    Packet.TotalSize = HeaderSize + DataSize;
    if (!NT_SUCCESS(AllocatePacketWithBuffer(&Packet.NdisPacket, NULL, Packet.TotalSize)))
    {
        NBDereferenceNeighbor(NCE);
        return;
    }

    GetDataPtr(Packet.NdisPacket, 0, (PCHAR *)&Packet.Header, &Contiguous);
    Packet.MappedHeader = TRUE;
    Packet.HeaderSize = HeaderSize;
    Packet.Data = (PCHAR)Packet.Header + HeaderSize;
    Packet.Flags |= IP_PACKET_FLAG_RAW;
    Packet.DstAddr = Destination;
    Packet.SrcAddr = Source;

    Header = Packet.Header;
    Header->VerIHL = 0x40 | (HeaderSize / 4);
    Header->Tos = 0;
    Header->TotalLength = WH2N((USHORT)Packet.TotalSize);
    Header->Id = (USHORT)Random();
    Header->FlagsFragOfs = 0;
    Header->Ttl = 1;
    Header->Protocol = IPPROTO_ICMP;
    Header->Checksum = 0;
    Header->SrcAddr = Source.Address.IPv4Address;
    Header->DstAddr = Destination.Address.IPv4Address;

    Icmp = Packet.Data;
    RtlZeroMemory(Icmp, DataSize);
    Icmp->Type = ICMP_TYPE_ROUTER_SOLICIT;
    Icmp->Checksum = (USHORT)IPv4Checksum(Icmp, DataSize, 0);

    IPSendDatagram(&Packet, NCE);
    NBDereferenceNeighbor(NCE);
}

static VOID RdiscSolicitWorker(PVOID Context)
{
    PRDISC_SOLICIT Solicit = Context;
    PIP_INTERFACE Interface = Solicit->Interface;
    KIRQL OldIrql;

    RdiscTransmitSolicitation(Interface);

    TcpipAcquireSpinLock(&RdiscLock, &OldIrql);
    Solicit->Queued = FALSE;
    TcpipReleaseSpinLock(&RdiscLock, OldIrql);
    IPDereferenceInterface(Interface);
}

VOID RdiscStart(PIP_INTERFACE Interface)
{
    PRDISC_SOLICIT Solicit, Fresh;
    KIRQL OldIrql;

    if (!RdiscEnabled(Interface))
        return;

    Fresh = ExAllocatePoolZero(NonPagedPool, sizeof(*Fresh), RDISC_TAG);
    if (!Fresh)
        return;

    TcpipAcquireSpinLock(&RdiscLock, &OldIrql);
    Solicit = RdiscFind(Interface);
    if (!Solicit)
    {
        Solicit = Fresh;
        Fresh = NULL;
        Solicit->Interface = Interface;
        InsertTailList(&RdiscSolicits, &Solicit->ListEntry);
    }
    Solicit->Remaining = RDISC_SOLICITATIONS;
    Solicit->Next = KeQueryInterruptTime() + (ULONGLONG)RDISC_FIRST_SOLICIT * 10000;
    TcpipReleaseSpinLock(&RdiscLock, OldIrql);

    if (Fresh)
        ExFreePoolWithTag(Fresh, RDISC_TAG);
}

VOID RdiscStop(PIP_INTERFACE Interface)
{
    PRDISC_SOLICIT Solicit;
    KIRQL OldIrql;

    TcpipAcquireSpinLock(&RdiscLock, &OldIrql);
    Solicit = RdiscFind(Interface);
    if (Solicit && !Solicit->Queued)
        RemoveEntryList(&Solicit->ListEntry);
    else if (Solicit)
    {
        Solicit->Remaining = 0;
        Solicit->ListenUntil = 0;
        Solicit = NULL;
    }
    TcpipReleaseSpinLock(&RdiscLock, OldIrql);

    if (Solicit)
        ExFreePoolWithTag(Solicit, RDISC_TAG);
    RouterRemoveAdvertisedRoutes(Interface, NULL);
}

VOID RdiscTimeout(VOID)
{
    ULONGLONG Now = KeQueryInterruptTime();
    PLIST_ENTRY Entry, Next;

    TcpipAcquireSpinLockAtDpcLevel(&RdiscLock);
    for (Entry = RdiscSolicits.Flink; Entry != &RdiscSolicits; Entry = Next)
    {
        PRDISC_SOLICIT Solicit = CONTAINING_RECORD(Entry, RDISC_SOLICIT, ListEntry);

        Next = Entry->Flink;
        if (Solicit->Queued)
            continue;
        if (!Solicit->Remaining)
        {
            if (Now > Solicit->ListenUntil)
            {
                RemoveEntryList(&Solicit->ListEntry);
                ExFreePoolWithTag(Solicit, RDISC_TAG);
            }
            continue;
        }
        if (Now < Solicit->Next || !IPReferenceInterface(Solicit->Interface))
            continue;

        Solicit->Remaining--;
        Solicit->Next = Now + (ULONGLONG)RDISC_SOLICIT_INTERVAL * 10000;
        Solicit->ListenUntil = Solicit->Next;
        Solicit->Queued = TRUE;
        if (!ChewCreate(RdiscSolicitWorker, Solicit))
        {
            Solicit->Queued = FALSE;
            IPDereferenceInterface(Solicit->Interface);
        }
    }
    TcpipReleaseSpinLockFromDpcLevel(&RdiscLock);
}

static BOOLEAN RdiscListening(PIP_INTERFACE Interface)
{
    PRDISC_SOLICIT Solicit;
    BOOLEAN Listening;
    KIRQL OldIrql;

    TcpipAcquireSpinLock(&RdiscLock, &OldIrql);
    Solicit = RdiscFind(Interface);
    Listening = Solicit && Solicit->ListenUntil && KeQueryInterruptTime() <= Solicit->ListenUntil;
    TcpipReleaseSpinLock(&RdiscLock, OldIrql);
    return Listening;
}

VOID RdiscReceive(PIP_INTERFACE Interface, PIP_PACKET IPPacket)
{
    PRDISC_ADVERT Advert = IPPacket->Data;
    UINT DataSize = IPPacket->TotalSize - IPPacket->HeaderSize;
    PULONG Entries;
    ULONG Lifetime, i;

    if (DataSize < sizeof(RDISC_ADVERT) || Advert->Code != 0 || !Advert->Addresses || Advert->EntrySize < 2 ||
        DataSize < sizeof(RDISC_ADVERT) + (ULONG)Advert->Addresses * Advert->EntrySize * sizeof(ULONG))
        return;
    if (!RdiscEnabled(Interface) || !RdiscListening(Interface) || !IsInterfaceOnLink(Interface, &IPPacket->SrcAddr))
        return;

    Lifetime = WN2H(Advert->Lifetime);
    Entries = (PULONG)(Advert + 1);
    for (i = 0; i < Advert->Addresses; i++, Entries += Advert->EntrySize)
    {
        IP_ADDRESS Router;
        LONG Preference = (LONG)DN2H(Entries[1]);

        AddrInitIPv4(&Router, Entries[0]);
        if (!IsInterfaceOnLink(Interface, &Router))
            continue;
        if (!Lifetime)
            RouterRemoveAdvertisedRoutes(Interface, &Router);
        else if ((ULONG)Preference != RDISC_NOT_DEFAULT)
            RouterSetAdvertisedRoute(Interface, &Router, (UINT)(0x7FFFFFFFLL - Preference), Lifetime);
    }
}

VOID RdiscStartup(VOID)
{
    InitializeListHead(&RdiscSolicits);
    KeInitializeSpinLock(&RdiscLock);
}
