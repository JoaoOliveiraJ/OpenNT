/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     IEEE 802.11 MAC header layout NetAdapterCx reads to demultiplex Wi-Fi peers
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#include <pshpack1.h>

typedef struct DOT11_MAC_HEADER
{
    USHORT FrameControl;
    USHORT DurationID;
    UCHAR Address1[6];
    UCHAR Address2[6];
    UCHAR Address3[6];
    USHORT SequenceControl;
} DOT11_MAC_HEADER, *PDOT11_MAC_HEADER;

#include <poppack.h>
