/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Assertion macros the NetAdapterCx sources take from ntassert.h
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#ifndef NT_FRE_ASSERT
#define NT_FRE_ASSERT(_exp) \
    ((!(_exp)) ? (DbgPrint("%s(%d): NT_FRE_ASSERT(%s)\n", __FILE__, __LINE__, #_exp), \
                  DbgRaiseAssertionFailure(), FALSE) : TRUE)
#endif

#ifndef NT_FRE_ASSERTMSG
#define NT_FRE_ASSERTMSG(_msg, _exp) \
    ((!(_exp)) ? (DbgPrint("%s(%d): NT_FRE_ASSERT(%s) %s\n", __FILE__, __LINE__, #_exp, _msg), \
                  DbgRaiseAssertionFailure(), FALSE) : TRUE)
#endif

#ifndef WIN_ASSERT
#define WIN_ASSERT(_exp) NT_ASSERT(_exp)
#endif

#ifndef WIN_VERIFY
#define WIN_VERIFY(_exp) NT_VERIFY(_exp)
#endif
