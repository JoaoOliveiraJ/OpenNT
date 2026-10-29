/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Batching library context layouts
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#define BL_LIB_CONTEXT_SIGNATURE 'bLxN'
#define BL_BUFFER_CONTEXT_SIGNATURE 'cBxN'

struct BL_LIB_CONTEXT
{
    ULONG Signature;
};

struct BL_BUFFER_CONTEXT
{
    ULONG Signature;
    BOOLEAN DispatchLevel;
    BL_LIB_CONTEXT * LibContext;
};
