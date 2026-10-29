/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Push lock wrappers NetAdapterCx uses
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#include <ntosp.h>
#include <kpushlock.h>

void
KPushLockBase::InitializeInner(
    void)
{
    ExInitializePushLock(&m_Lock);
#if DBG
    m_ExclusiveOwner = nullptr;
#endif
}

void
KPushLockBase::AcquireShared(
    void)
{
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&m_Lock);
}

void
KPushLockBase::ReleaseShared(
    void)
{
    ExReleasePushLockShared(&m_Lock);
    KeLeaveCriticalRegion();
}

void
KPushLockBase::AcquireExclusive(
    void)
{
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&m_Lock);
#if DBG
    m_ExclusiveOwner = KeGetCurrentThread();
#endif
}

void
KPushLockBase::ReleaseExclusive(
    void)
{
#if DBG
    NT_ASSERT(m_ExclusiveOwner == KeGetCurrentThread());
    m_ExclusiveOwner = nullptr;
#endif
    ExReleasePushLockExclusive(&m_Lock);
    KeLeaveCriticalRegion();
}

void
KPushLockBase::AssertLockHeld(
    void)
{
#if DBG
    NT_ASSERT(m_ExclusiveOwner == KeGetCurrentThread());
#endif
}

void
KPushLockBase::AssertLockNotHeld(
    void)
{
#if DBG
    NT_ASSERT(m_ExclusiveOwner != KeGetCurrentThread());
#endif
}

KPushLock::KPushLock(
    void) noexcept
{
    InitializeInner();
}

KPushLock::~KPushLock(
    void)
{
}

void
KPushLockManualConstruct::Initialize(
    void)
{
    InitializeInner();
}
