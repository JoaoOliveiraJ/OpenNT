/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Kernel stopwatches NetAdapterCx uses to time work
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

class KStopwatch
{
public:

    void
    Start()
    {
        m_startTime = KeQueryPerformanceCounter(reinterpret_cast<LARGE_INTEGER *>(&m_frequency)).QuadPart;
    }

    ULONG64
    Stop()
    {
        m_stopTime = KeQueryPerformanceCounter(nullptr).QuadPart;
        return GetElapsedTimeInMilliseconds();
    }

    ULONG64
    GetElapsedTimeInMilliseconds() const
    {
        return Elapsed(1000);
    }

    ULONG64
    GetElapsedTimeInMicroseconds() const
    {
        return Elapsed(1000 * 1000);
    }

private:

    ULONG64
    Elapsed(
        _In_ LONG64 UnitsPerSecond) const
    {
        if (m_frequency == 0 || m_stopTime < m_startTime)
        {
            return 0;
        }

        return static_cast<ULONG64>((m_stopTime - m_startTime) * UnitsPerSecond / m_frequency);
    }

    LONG64 m_startTime = 0;
    LONG64 m_frequency = 0;
    LONG64 m_stopTime = 0;
};

class KTickCounterStopwatch
{
public:

    void
    Start()
    {
        KeQueryTickCount(&m_startTicks);
    }

    ULONG64
    Stop()
    {
        KeQueryTickCount(&m_stopTicks);
        return GetElapsedTimeInMilliseconds();
    }

    ULONG64
    GetElapsedTimeInMilliseconds() const
    {
        if (m_stopTicks.QuadPart < m_startTicks.QuadPart)
        {
            return 0;
        }

        return static_cast<ULONG64>(m_stopTicks.QuadPart - m_startTicks.QuadPart) * KeQueryTimeIncrement() / 10000;
    }

private:

    LARGE_INTEGER m_startTicks = {};
    LARGE_INTEGER m_stopTicks = {};
};
