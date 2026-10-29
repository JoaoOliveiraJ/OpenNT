/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Histogram output layouts of the NDIS statistics IOCTLs
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

enum class NDIS_HISTOGRAM_AUXILIARY_DATATYPE : ULONG
{
    None = 0,
    MacAddress = 1,
    NetLuid = 2,
};

typedef struct _NDIS_SINGLE_HISTOGRAM_ENTRY
{
    ULONG64 TimestampUs;
    ULONG Reserved1;
    NDIS_HISTOGRAM_AUXILIARY_DATATYPE AuxiliaryDataType;
    union
    {
        UCHAR MacAddress[6];
        ULONG64 NetLuid;
        ULONG64 Reserved2[2];
    };
    WCHAR Name[128];
    USHORT Buckets[1];
} NDIS_SINGLE_HISTOGRAM_ENTRY;

typedef struct _NDIS_COLLECT_HISTOGRAM_OUT
{
    ULONG NumHistograms;
    ULONG HistogramEntryStride;
    ULONG Reserved1;
    ULONG NumBucketsPerHistogram;
    ULONG64 SmallestBucketValue;
    ULONG64 BucketWidth;
    ULONG64 Reserved2[4];
    WCHAR Name[128];
    NDIS_SINGLE_HISTOGRAM_ENTRY Histograms[1];
} NDIS_COLLECT_HISTOGRAM_OUT;

C_ASSERT(sizeof(NDIS_SINGLE_HISTOGRAM_ENTRY) == 296);
C_ASSERT(FIELD_OFFSET(NDIS_SINGLE_HISTOGRAM_ENTRY, Name) == 0x20);
C_ASSERT(FIELD_OFFSET(NDIS_SINGLE_HISTOGRAM_ENTRY, Buckets) == 0x120);
C_ASSERT(sizeof(NDIS_COLLECT_HISTOGRAM_OUT) == 616);
C_ASSERT(FIELD_OFFSET(NDIS_COLLECT_HISTOGRAM_OUT, Name) == 0x40);
C_ASSERT(FIELD_OFFSET(NDIS_COLLECT_HISTOGRAM_OUT, Histograms) == 0x140);
