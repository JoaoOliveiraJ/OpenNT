/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Module loader types NetAdapterCx uses to reach its execution contexts
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

DECLARE_HANDLE(KLOADER_MODULE_REFERENCE);

typedef struct _KLOADER_REFERENCE_MODULE_CONFIG
{
    SIZE_T Size;
    GUID ModuleID;
} KLOADER_REFERENCE_MODULE_CONFIG;

typedef struct _KLOADER_DISPATCH_TABLE
{
    SIZE_T Size;
} KLOADER_DISPATCH_TABLE;
