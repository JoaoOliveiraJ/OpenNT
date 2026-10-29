/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     C++ objects that live in the context of a WDF object
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#include <kptr.h>

#include <wdf.h>

template <typename TFxHandle, typename TObject, TObject * (*TGetObject)(TFxHandle), bool TCallOnCleanup>
class CFxObject
{
public:

    virtual
    ~CFxObject() = default;

    TFxHandle
    GetFxObject() const
    {
        return m_FxObject;
    }

    bool
    IsConstructed() const
    {
        return m_Constructed;
    }

    static
    TObject *
    _FromFxObject(
        _In_ TFxHandle FxObject)
    {
        return TGetObject(FxObject);
    }

    static
    TObject *
    _FromFxBaseObject(
        _In_ WDFOBJECT FxObject)
    {
        return TGetObject(static_cast<TFxHandle>(FxObject));
    }

    static
    void
    _SetObjectAttributes(
        _Inout_ WDF_OBJECT_ATTRIBUTES * Attributes)
    {
        Attributes->EvtDestroyCallback = _OnDestroy;
        if (TCallOnCleanup)
        {
            Attributes->EvtCleanupCallback = _OnCleanup;
        }
    }

    void *
    operator new(
        size_t,
        _In_ void * Memory)
    {
        return Memory;
    }

    void
    operator delete(
        void *,
        void *)
    {
    }

    void
    operator delete(
        void *)
    {
    }

protected:

    CFxObject(
        _In_ TFxHandle FxObject)
        : m_FxObject(FxObject)
        , m_Constructed(true)
    {
    }

    virtual
    void
    OnCleanup()
    {
    }

private:

    static
    void
    _OnCleanup(
        _In_ WDFOBJECT FxObject)
    {
        auto object = TGetObject(static_cast<TFxHandle>(FxObject));
        if (object->m_Constructed)
        {
            object->OnCleanup();
        }
    }

    static
    void
    _OnDestroy(
        _In_ WDFOBJECT FxObject)
    {
        auto object = TGetObject(static_cast<TFxHandle>(FxObject));
        if (object->m_Constructed)
        {
            object->~TObject();
        }
    }

    TFxHandle const m_FxObject;
    bool m_Constructed;
};

struct CFxObjectDeleter
{
    template <typename TFxObject>
    void
    operator()(
        _In_ TFxObject * Object) const
    {
        WdfObjectDelete(Object->GetFxObject());
    }
};
