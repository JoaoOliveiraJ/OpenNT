/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     I/O work item that runs a member function of its owner
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

DRIVER_OBJECT *
GetTranslatorDriverObject(
    void);

template <typename TOwner, void (TOwner::*Method)(void), typename TIoObject>
class IoWorkItem
{
public:

    explicit
    IoWorkItem(
        _In_ TOwner * Owner) :
        m_owner(Owner)
    {
    }

    ~IoWorkItem(
        void)
    {
        if (m_workItem != nullptr)
        {
            IoUninitializeWorkItem(m_workItem);
            ExFreePoolWithTag(m_workItem, 'IWxN');
        }
    }

    IoWorkItem(IoWorkItem const &) = delete;
    IoWorkItem & operator=(IoWorkItem const &) = delete;

    _IRQL_requires_max_(PASSIVE_LEVEL)
    NTSTATUS
    Initialize(
        _In_ TIoObject * IoObject)
    {
        auto workItem = static_cast<PIO_WORKITEM>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, IoSizeofWorkItem(), 'IWxN'));

        if (workItem == nullptr)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        IoInitializeWorkItem(IoObject, workItem);
        m_workItem = workItem;
        return STATUS_SUCCESS;
    }

    _IRQL_requires_max_(DISPATCH_LEVEL)
    void
    Queue(
        void)
    {
        IoQueueWorkItemEx(m_workItem, &IoWorkItem::Callback, DelayedWorkQueue, this);
    }

private:

    static
    _Function_class_(IO_WORKITEM_ROUTINE_EX)
    void
    Callback(
        _In_ PVOID IoObject,
        _In_opt_ PVOID Context,
        _In_ PIO_WORKITEM WorkItem)
    {
        UNREFERENCED_PARAMETER(IoObject);
        UNREFERENCED_PARAMETER(WorkItem);

        auto self = static_cast<IoWorkItem *>(Context);
        (self->m_owner->*Method)();
    }

    TOwner *
        m_owner;

    PIO_WORKITEM
        m_workItem = nullptr;
};
