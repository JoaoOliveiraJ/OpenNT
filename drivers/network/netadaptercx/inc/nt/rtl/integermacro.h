/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Integer helper macros NetAdapterCx takes from nt/rtl/integermacro.h
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#ifndef RTL_IS_POWER_OF_TWO
#define RTL_IS_POWER_OF_TWO(_Value) (((_Value) != 0) && (((_Value) & ((_Value) - 1)) == 0))
#endif

#ifndef RTL_NUM_ALIGN_DOWN
#define RTL_NUM_ALIGN_DOWN(_Number, _Alignment) ((_Number) - ((_Number) & ((_Alignment) - 1)))
#endif

#ifndef RTL_NUM_ALIGN_UP
#define RTL_NUM_ALIGN_UP(_Number, _Alignment) RTL_NUM_ALIGN_DOWN((_Number) + (_Alignment) - 1, (_Alignment))
#endif
