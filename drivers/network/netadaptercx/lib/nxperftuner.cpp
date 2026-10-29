/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Ring and pool sizes of the NBL translator
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#include <ntosp.h>
#include <ndk/exfuncs.h>
#include <ntassert.h>
#include <nxperftuner.hpp>

static ULONG64 g_TotalPhysicalBytes;

static constexpr ULONG64 OneGigabyte = 0x40000000ULL;
static constexpr ULONG64 TwoGigabytes = 0x80000000ULL;
static constexpr ULONG64 SixtyFourGigabytes = 0x1000000000ULL;
static constexpr ULONG64 HighLinkSpeed = 0x240000000ULL;
static constexpr ULONG64 WifiHighLinkSpeed = 0x80000000ULL;
static constexpr ULONG64 UnknownLinkSpeed = MAXULONG64;

static
bool
IsPowerOfTwo(
    _In_ UINT32 Value)
{
    return Value != 0 && (Value & (Value - 1)) == 0;
}

static
bool
IsHighSpeedLink(
    _In_ ULONG64 NominalLinkSpeed)
{
    return NominalLinkSpeed >= HighLinkSpeed && NominalLinkSpeed != UnknownLinkSpeed;
}

static
UINT32
FragmentRingSize(
    _In_ NX_PERF_NIC_GENERAL_CHARACTERISTICS const & Nic,
    _In_ UINT32 Hint,
    _In_ UINT32 Minimum)
{
    if (Nic.IsDriverVerifierEnabled)
    {
        return Minimum * 2;
    }

    if (Hint < Minimum)
    {
        return Minimum;
    }

    return min(Hint, Minimum * 4);
}

_Use_decl_annotations_
NTSTATUS
NxPerfTunerInitialize(
    void)
{
    SYSTEM_PHYSICAL_MEMORY_INFORMATION information = {};

    NTSTATUS status = ZwQuerySystemInformation(
        SystemPhysicalMemoryInformation,
        &information,
        sizeof(information),
        nullptr);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    g_TotalPhysicalBytes = information.TotalPhysicalBytes;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
void
NxPerfTunerCleanup(
    void)
{
    g_TotalPhysicalBytes = 0;
}

_Use_decl_annotations_
void
NxPerfTunerCalculateRxParameters(
    NX_PERF_RX_NIC_CHARACTERISTICS const * Characteristics,
    NX_PERF_RX_TUNING_PARAMETERS * Parameters)
{
    UINT32 minimum;
    UINT32 poolMultiplier;

    if (g_TotalPhysicalBytes <= OneGigabyte)
    {
        minimum = 32;
        poolMultiplier = 1;
    }
    else if (g_TotalPhysicalBytes > SixtyFourGigabytes ||
             (g_TotalPhysicalBytes >= TwoGigabytes && IsHighSpeedLink(Characteristics->NominalLinkSpeed)))
    {
        minimum = 4096;
        poolMultiplier = 4;
    }
    else
    {
        minimum = 256;
        poolMultiplier = 2;
    }

    UINT32 const fragments = FragmentRingSize(
        Characteristics->Nic,
        Characteristics->FragmentRingNumberOfElementsHint,
        minimum);

    Parameters->FragmentRingElementCount = fragments;
    Parameters->PacketRingElementCount = fragments;
    Parameters->NumberOfNbls = fragments * poolMultiplier;
    Parameters->NumberOfBuffers = fragments * poolMultiplier;

    NT_FRE_ASSERT(IsPowerOfTwo(Parameters->PacketRingElementCount));
    NT_FRE_ASSERT(IsPowerOfTwo(Parameters->FragmentRingElementCount));
}

_Use_decl_annotations_
void
NxPerfTunerCalculateTxParameters(
    NX_PERF_TX_NIC_CHARACTERISTICS const * Characteristics,
    NX_PERF_TX_TUNING_PARAMETERS * Parameters)
{
    UINT32 packets;
    UINT32 fragmentsPerPacket;

    if (g_TotalPhysicalBytes <= OneGigabyte)
    {
        packets = 32;
        fragmentsPerPacket = 4;
    }
    else if (g_TotalPhysicalBytes > SixtyFourGigabytes ||
             (g_TotalPhysicalBytes >= TwoGigabytes && IsHighSpeedLink(Characteristics->NominalLinkSpeed)))
    {
        packets = 4096;
        fragmentsPerPacket = 16;
    }
    else if (g_TotalPhysicalBytes >= TwoGigabytes &&
             Characteristics->Nic.MediaType == NdisMediumNative802_11 &&
             Characteristics->NominalLinkSpeed >= WifiHighLinkSpeed)
    {
        packets = 1024;
        fragmentsPerPacket = 2;
    }
    else
    {
        packets = 256;
        fragmentsPerPacket = 4;
    }

    ULONG const maxFragmentsPerPacket = Characteristics->MaxFragmentsPerPacket;

    if (maxFragmentsPerPacket != 0 && maxFragmentsPerPacket < fragmentsPerPacket)
    {
        fragmentsPerPacket = 1;

        while (fragmentsPerPacket < maxFragmentsPerPacket)
        {
            fragmentsPerPacket *= 2;
        }
    }

    if (Characteristics->MaxPacketSizeWithGso < 1551 && fragmentsPerPacket > 4)
    {
        fragmentsPerPacket = 4;
    }

    UINT32 const fragments = FragmentRingSize(
        Characteristics->Nic,
        Characteristics->FragmentRingNumberOfElementsHint,
        packets * fragmentsPerPacket);

    Parameters->FragmentRingElementCount = fragments;
    Parameters->PacketRingElementCount = fragments / fragmentsPerPacket;
    Parameters->NumberOfBounceBuffers = Characteristics->MaximumFragmentBufferSize <= 2048
        ? Parameters->PacketRingElementCount
        : 256;

    NT_FRE_ASSERT(IsPowerOfTwo(Parameters->PacketRingElementCount));
    NT_FRE_ASSERT(IsPowerOfTwo(Parameters->FragmentRingElementCount));
}
