/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Ring and pool sizes of the NBL translator
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

struct NX_PERF_NIC_GENERAL_CHARACTERISTICS
{
    ULONG MediaType;
    bool IsDriverVerifierEnabled;
};

struct NX_PERF_RX_NIC_CHARACTERISTICS
{
    NX_PERF_NIC_GENERAL_CHARACTERISTICS Nic;
    UINT32 FragmentRingNumberOfElementsHint;
    ULONG64 MaximumFragmentBufferSize;
    ULONG64 MaxPacketSizeWithRsc;
    ULONG64 NominalLinkSpeed;
};

struct NX_PERF_RX_TUNING_PARAMETERS
{
    UINT32 PacketRingElementCount;
    UINT32 FragmentRingElementCount;
    ULONG NumberOfBuffers;
    ULONG NumberOfNbls;
};

struct NX_PERF_TX_NIC_CHARACTERISTICS
{
    NX_PERF_NIC_GENERAL_CHARACTERISTICS Nic;
    UINT32 FragmentRingNumberOfElementsHint;
    ULONG64 MaximumFragmentBufferSize;
    ULONG MaxFragmentsPerPacket;
    ULONG64 MaxPacketSizeWithGso;
    ULONG64 NominalLinkSpeed;
};

struct NX_PERF_TX_TUNING_PARAMETERS
{
    UINT32 PacketRingElementCount;
    UINT32 FragmentRingElementCount;
    UINT32 NumberOfBounceBuffers;
};

static_assert(sizeof(NX_PERF_NIC_GENERAL_CHARACTERISTICS) == 8);
static_assert(sizeof(NX_PERF_RX_NIC_CHARACTERISTICS) == 40);
static_assert(sizeof(NX_PERF_RX_TUNING_PARAMETERS) == 16);
static_assert(sizeof(NX_PERF_TX_NIC_CHARACTERISTICS) == 48);
static_assert(FIELD_OFFSET(NX_PERF_TX_NIC_CHARACTERISTICS, MaxPacketSizeWithGso) == 0x20);
static_assert(sizeof(NX_PERF_TX_TUNING_PARAMETERS) == 12);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NxPerfTunerInitialize(
    void);

_IRQL_requires_(PASSIVE_LEVEL)
void
NxPerfTunerCleanup(
    void);

void
NxPerfTunerCalculateRxParameters(
    _In_ NX_PERF_RX_NIC_CHARACTERISTICS const * Characteristics,
    _Out_ NX_PERF_RX_TUNING_PARAMETERS * Parameters);

void
NxPerfTunerCalculateTxParameters(
    _In_ NX_PERF_TX_NIC_CHARACTERISTICS const * Characteristics,
    _Out_ NX_PERF_TX_TUNING_PARAMETERS * Parameters);
