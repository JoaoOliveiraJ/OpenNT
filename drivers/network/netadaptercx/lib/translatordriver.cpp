/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Driver object the NBL translator queues its work items against
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#include <ntosp.h>
#include <wdf.h>
#include <ioworkitem.hpp>

DRIVER_OBJECT *
GetTranslatorDriverObject(
    void)
{
    return WdfDriverWdmGetDriverObject(WdfGetDriver());
}
