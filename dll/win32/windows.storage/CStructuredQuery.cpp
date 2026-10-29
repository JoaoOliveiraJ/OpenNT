/*
 * PROJECT:     OpenNT Windows Storage
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Structured query conditions, condition factory and condition evaluation
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif.ing@outlook.com>
 */

#include "precomp.h"
#include <propvarutil.h>
#include <propkey.h>
#include "CSearch.h"

#define CONDITION_STREAM_MAGIC 0x5153424CUL

typedef CComEnum<IEnumUnknown, &IID_IEnumUnknown, IUnknown *, _CopyInterface<IUnknown> > CEnumUnknown;

static HRESULT
DupString(LPCWSTR pszSrc, CComHeapPtr<WCHAR> &Dest)
{
    Dest.Free();
    if (!pszSrc)
        return S_OK;
    return SHStrDupW(pszSrc, &Dest);
}

static HRESULT
CopyOutString(LPCWSTR pszSrc, LPWSTR *ppszDest)
{
    *ppszDest = NULL;
    if (!pszSrc)
        return S_OK;
    return SHStrDupW(pszSrc, ppszDest);
}

static HRESULT
WriteString(IStream *pStream, LPCWSTR psz)
{
    DWORD cch = psz ? (DWORD)wcslen(psz) + 1 : 0;
    HRESULT hr = pStream->Write(&cch, sizeof(cch), NULL);
    if (SUCCEEDED(hr) && cch)
        hr = pStream->Write(psz, cch * sizeof(WCHAR), NULL);
    return hr;
}

static HRESULT
ReadExact(IStream *pStream, void *pv, ULONG cb)
{
    ULONG cbRead = 0;
    HRESULT hr = pStream->Read(pv, cb, &cbRead);
    if (FAILED(hr))
        return hr;
    return (cbRead == cb) ? S_OK : STG_E_READFAULT;
}

static HRESULT
ReadString(IStream *pStream, CComHeapPtr<WCHAR> &Dest)
{
    DWORD cch;
    Dest.Free();
    HRESULT hr = ReadExact(pStream, &cch, sizeof(cch));
    if (FAILED(hr) || !cch)
        return hr;
    if (cch > 0x8000 || !Dest.Allocate(cch))
        return E_OUTOFMEMORY;
    hr = ReadExact(pStream, (LPWSTR)Dest, cch * sizeof(WCHAR));
    if (SUCCEEDED(hr))
        Dest[cch - 1] = UNICODE_NULL;
    return hr;
}

class CCondition :
    public CComObjectRootEx<CComMultiThreadModelNoCS>,
    public ICondition2
{
protected:
    CONDITION_TYPE m_Type;
    CONDITION_OPERATION m_Op;
    CComHeapPtr<WCHAR> m_pszProperty;
    CComHeapPtr<WCHAR> m_pszValueType;
    CComHeapPtr<WCHAR> m_pszLocale;
    PROPVARIANT m_Value;
    CComPtr<IRichChunk> m_pPropertyTerm;
    CComPtr<IRichChunk> m_pOperationTerm;
    CComPtr<IRichChunk> m_pValueTerm;
    CSimpleArray<ICondition *> m_Subs;

public:
    CCondition() : m_Type(CT_LEAF_CONDITION), m_Op(COP_IMPLICIT)
    {
        PropVariantInit(&m_Value);
    }

    virtual ~CCondition()
    {
        ClearSubs();
        PropVariantClear(&m_Value);
    }

    void ClearSubs()
    {
        for (INT i = 0; i < m_Subs.GetSize(); ++i)
            m_Subs[i]->Release();
        m_Subs.RemoveAll();
    }

    void SetType(CONDITION_TYPE Type)
    {
        m_Type = Type;
    }

    HRESULT AddSub(ICondition *pSub)
    {
        if (!pSub)
            return E_INVALIDARG;
        if (!m_Subs.Add(pSub))
            return E_OUTOFMEMORY;
        pSub->AddRef();
        return S_OK;
    }

    HRESULT SetLeaf(LPCWSTR pszProperty, CONDITION_OPERATION Op, LPCWSTR pszValueType,
                    const PROPVARIANT *pValue, LPCWSTR pszLocale, IRichChunk *pPropertyTerm,
                    IRichChunk *pOperationTerm, IRichChunk *pValueTerm)
    {
        HRESULT hr = DupString(pszProperty, m_pszProperty);
        if (SUCCEEDED(hr))
            hr = DupString(pszValueType, m_pszValueType);
        if (SUCCEEDED(hr))
            hr = DupString(pszLocale, m_pszLocale);
        if (FAILED(hr))
            return hr;
        PropVariantClear(&m_Value);
        if (pValue)
        {
            hr = PropVariantCopy(&m_Value, pValue);
            if (FAILED(hr))
                return hr;
        }
        m_Op = Op;
        m_pPropertyTerm = pPropertyTerm;
        m_pOperationTerm = pOperationTerm;
        m_pValueTerm = pValueTerm;
        return S_OK;
    }

    STDMETHOD(GetClassID)(CLSID *pClassID) override
    {
        if (!pClassID)
            return E_POINTER;
        if (m_Type == CT_LEAF_CONDITION)
            *pClassID = CLSID_LeafCondition;
        else if (m_Type == CT_NOT_CONDITION)
            *pClassID = CLSID_NegationCondition;
        else
            *pClassID = CLSID_CompoundCondition;
        return S_OK;
    }

    STDMETHOD(IsDirty)() override
    {
        return S_FALSE;
    }

    STDMETHOD(Load)(IStream *pStream) override
    {
        DWORD Header[4], cbValue, cSubs;
        HRESULT hr;

        if (!pStream)
            return E_POINTER;
        hr = ReadExact(pStream, Header, sizeof(Header));
        if (FAILED(hr))
            return hr;
        if (Header[0] != CONDITION_STREAM_MAGIC || Header[1] != 1)
            return E_INVALIDARG;
        m_Type = (CONDITION_TYPE)Header[2];
        m_Op = (CONDITION_OPERATION)Header[3];
        hr = ReadString(pStream, m_pszProperty);
        if (SUCCEEDED(hr))
            hr = ReadString(pStream, m_pszValueType);
        if (SUCCEEDED(hr))
            hr = ReadString(pStream, m_pszLocale);
        if (SUCCEEDED(hr))
            hr = ReadExact(pStream, &cbValue, sizeof(cbValue));
        if (FAILED(hr))
            return hr;
        PropVariantClear(&m_Value);
        if (cbValue)
        {
            CComHeapPtr<BYTE> pBuffer;
            if (cbValue > 0x100000 || !pBuffer.Allocate(cbValue))
                return E_OUTOFMEMORY;
            hr = ReadExact(pStream, (BYTE *)pBuffer, cbValue);
            if (SUCCEEDED(hr))
                hr = StgDeserializePropVariant((const SERIALIZEDPROPERTYVALUE *)(BYTE *)pBuffer, cbValue, &m_Value);
            if (FAILED(hr))
                return hr;
        }
        hr = ReadExact(pStream, &cSubs, sizeof(cSubs));
        if (FAILED(hr))
            return hr;
        ClearSubs();
        for (DWORD i = 0; i < cSubs; ++i)
        {
            CComPtr<ICondition> pSub;
            hr = OleLoadFromStream(pStream, IID_PPV_ARG(ICondition, &pSub));
            if (FAILED(hr))
                return hr;
            hr = AddSub(pSub);
            if (FAILED(hr))
                return hr;
        }
        return S_OK;
    }

    STDMETHOD(Save)(IStream *pStream, BOOL fClearDirty) override
    {
        DWORD Header[4] = { CONDITION_STREAM_MAGIC, 1, (DWORD)m_Type, (DWORD)m_Op };
        DWORD cbValue = 0, cSubs = m_Subs.GetSize();
        SERIALIZEDPROPERTYVALUE *pValue = NULL;
        HRESULT hr;

        if (!pStream)
            return E_POINTER;
        if (m_Value.vt != VT_EMPTY)
        {
            hr = StgSerializePropVariant(&m_Value, &pValue, &cbValue);
            if (FAILED(hr))
                return hr;
        }
        hr = pStream->Write(Header, sizeof(Header), NULL);
        if (SUCCEEDED(hr))
            hr = WriteString(pStream, m_pszProperty);
        if (SUCCEEDED(hr))
            hr = WriteString(pStream, m_pszValueType);
        if (SUCCEEDED(hr))
            hr = WriteString(pStream, m_pszLocale);
        if (SUCCEEDED(hr))
            hr = pStream->Write(&cbValue, sizeof(cbValue), NULL);
        if (SUCCEEDED(hr) && cbValue)
            hr = pStream->Write(pValue, cbValue, NULL);
        CoTaskMemFree(pValue);
        if (SUCCEEDED(hr))
            hr = pStream->Write(&cSubs, sizeof(cSubs), NULL);
        for (INT i = 0; SUCCEEDED(hr) && i < m_Subs.GetSize(); ++i)
        {
            CComPtr<IPersistStream> pPersist;
            hr = m_Subs[i]->QueryInterface(IID_PPV_ARG(IPersistStream, &pPersist));
            if (SUCCEEDED(hr))
                hr = OleSaveToStream(pPersist, pStream);
        }
        return hr;
    }

    STDMETHOD(GetSizeMax)(ULARGE_INTEGER *pcbSize) override
    {
        if (!pcbSize)
            return E_POINTER;
        CComPtr<IStream> pStream;
        pStream.Attach(SHCreateMemStream(NULL, 0));
        if (!pStream)
            return E_OUTOFMEMORY;
        HRESULT hr = Save(pStream, FALSE);
        if (FAILED(hr))
            return hr;
        LARGE_INTEGER Zero = {};
        return pStream->Seek(Zero, STREAM_SEEK_CUR, pcbSize);
    }

    STDMETHOD(GetConditionType)(CONDITION_TYPE *pNodeType) override
    {
        if (!pNodeType)
            return E_POINTER;
        *pNodeType = m_Type;
        return S_OK;
    }

    STDMETHOD(GetSubConditions)(REFIID riid, void **ppv) override
    {
        if (!ppv)
            return E_POINTER;
        *ppv = NULL;

        if (m_Type == CT_NOT_CONDITION && IsEqualIID(riid, IID_ICondition))
            return m_Subs.GetSize() ? m_Subs[0]->QueryInterface(riid, ppv) : E_FAIL;

        if (IsEqualIID(riid, IID_IEnumUnknown))
        {
            CComObject<CEnumUnknown> *pEnum;
            HRESULT hr = CComObject<CEnumUnknown>::CreateInstance(&pEnum);
            if (FAILED(hr))
                return hr;
            CComPtr<IEnumUnknown> pResult(pEnum);
            IUnknown **ppBegin = (IUnknown **)m_Subs.GetData();
            hr = pEnum->Init(ppBegin, ppBegin + m_Subs.GetSize(), NULL, AtlFlagCopy);
            if (FAILED(hr))
                return hr;
            *ppv = pResult.Detach();
            return S_OK;
        }

        if (IsEqualIID(riid, IID_IObjectArray) || IsEqualIID(riid, IID_IObjectCollection))
        {
            CComPtr<IObjectCollection> pCollection;
            HRESULT hr = ShellObjectCreator<CEnumerableObjectCollection>(IID_PPV_ARG(IObjectCollection, &pCollection));
            for (INT i = 0; SUCCEEDED(hr) && i < m_Subs.GetSize(); ++i)
                hr = pCollection->AddObject(m_Subs[i]);
            if (FAILED(hr))
                return hr;
            return pCollection->QueryInterface(riid, ppv);
        }

        return E_NOINTERFACE;
    }

    STDMETHOD(GetComparisonInfo)(LPWSTR *ppszPropertyName, CONDITION_OPERATION *pcop, PROPVARIANT *ppropvar) override
    {
        HRESULT hr = S_OK;

        if (m_Type != CT_LEAF_CONDITION)
            return E_FAIL;
        if (ppszPropertyName)
            hr = CopyOutString(m_pszProperty, ppszPropertyName);
        if (SUCCEEDED(hr) && pcop)
            *pcop = m_Op;
        if (SUCCEEDED(hr) && ppropvar)
        {
            PropVariantInit(ppropvar);
            hr = PropVariantCopy(ppropvar, &m_Value);
        }
        if (FAILED(hr) && ppszPropertyName)
        {
            CoTaskMemFree(*ppszPropertyName);
            *ppszPropertyName = NULL;
        }
        return hr;
    }

    STDMETHOD(GetValueType)(LPWSTR *ppszValueTypeName) override
    {
        if (!ppszValueTypeName)
            return E_POINTER;
        *ppszValueTypeName = NULL;
        if (m_Type != CT_LEAF_CONDITION)
            return E_FAIL;
        return CopyOutString(m_pszValueType, ppszValueTypeName);
    }

    STDMETHOD(GetValueNormalization)(LPWSTR *ppszNormalization) override
    {
        if (!ppszNormalization)
            return E_POINTER;
        *ppszNormalization = NULL;
        if (m_Type != CT_LEAF_CONDITION)
            return E_FAIL;
        return PropVariantToStringAlloc(m_Value, ppszNormalization);
    }

    STDMETHOD(GetInputTerms)(IRichChunk **ppPropertyTerm, IRichChunk **ppOperationTerm, IRichChunk **ppValueTerm) override
    {
        if (m_Type != CT_LEAF_CONDITION)
            return E_FAIL;
        if (ppPropertyTerm)
            *ppPropertyTerm = CComPtr<IRichChunk>(m_pPropertyTerm).Detach();
        if (ppOperationTerm)
            *ppOperationTerm = CComPtr<IRichChunk>(m_pOperationTerm).Detach();
        if (ppValueTerm)
            *ppValueTerm = CComPtr<IRichChunk>(m_pValueTerm).Detach();
        return S_OK;
    }

    STDMETHOD(Clone)(ICondition **ppc) override;

    STDMETHOD(GetLocale)(LPWSTR *ppszLocaleName) override
    {
        if (!ppszLocaleName)
            return E_POINTER;
        return CopyOutString(m_pszLocale, ppszLocaleName);
    }

    STDMETHOD(GetLeafConditionInfo)(PROPERTYKEY *ppropkey, CONDITION_OPERATION *pcop, PROPVARIANT *ppropvar) override
    {
        HRESULT hr = S_OK;

        if (m_Type != CT_LEAF_CONDITION)
            return E_FAIL;
        if (ppropkey)
        {
            if (!m_pszProperty)
                return E_FAIL;
            hr = PSGetPropertyKeyFromName(m_pszProperty, ppropkey);
            if (FAILED(hr))
                return hr;
        }
        if (pcop)
            *pcop = m_Op;
        if (ppropvar)
        {
            PropVariantInit(ppropvar);
            hr = PropVariantCopy(ppropvar, &m_Value);
        }
        return hr;
    }

    BEGIN_COM_MAP(CCondition)
        COM_INTERFACE_ENTRY_IID(IID_ICondition2, ICondition2)
        COM_INTERFACE_ENTRY_IID(IID_ICondition, ICondition)
        COM_INTERFACE_ENTRY_IID(IID_IPersistStream, IPersistStream)
        COM_INTERFACE_ENTRY_IID(IID_IPersist, IPersist)
    END_COM_MAP()
};

#define DECLARE_CONDITION_CLASS(Name, Type, Clsid) \
    class Name : \
        public CCondition, \
        public CComCoClass<Name, &Clsid> \
    { \
    public: \
        Name() \
        { \
            m_Type = Type; \
        } \
        DECLARE_NO_REGISTRY() \
        DECLARE_NOT_AGGREGATABLE(Name) \
        DECLARE_PROTECT_FINAL_CONSTRUCT() \
    };

DECLARE_CONDITION_CLASS(CLeafCondition, CT_LEAF_CONDITION, CLSID_LeafCondition)
DECLARE_CONDITION_CLASS(CCompoundCondition, CT_AND_CONDITION, CLSID_CompoundCondition)
DECLARE_CONDITION_CLASS(CNegationCondition, CT_NOT_CONDITION, CLSID_NegationCondition)

OBJECT_ENTRY_AUTO(CLSID_LeafCondition, CLeafCondition)
OBJECT_ENTRY_AUTO(CLSID_CompoundCondition, CCompoundCondition)
OBJECT_ENTRY_AUTO(CLSID_NegationCondition, CNegationCondition)

template <class T>
static HRESULT
CreateConditionObject(CCondition **ppCondition)
{
    CComObject<T> *pObject;
    HRESULT hr = CComObject<T>::CreateInstance(&pObject);
    if (FAILED(hr))
        return hr;
    pObject->AddRef();
    *ppCondition = pObject;
    return S_OK;
}

static HRESULT
CreateCondition(CONDITION_TYPE Type, CCondition **ppCondition)
{
    HRESULT hr;

    *ppCondition = NULL;
    switch (Type)
    {
        case CT_LEAF_CONDITION:
            return CreateConditionObject<CLeafCondition>(ppCondition);
        case CT_NOT_CONDITION:
            return CreateConditionObject<CNegationCondition>(ppCondition);
        case CT_AND_CONDITION:
        case CT_OR_CONDITION:
            hr = CreateConditionObject<CCompoundCondition>(ppCondition);
            if (SUCCEEDED(hr))
                (*ppCondition)->SetType(Type);
            return hr;
        default:
            return E_INVALIDARG;
    }
}

STDMETHODIMP
CCondition::Clone(ICondition **ppc)
{
    CCondition *pClone;

    if (!ppc)
        return E_POINTER;
    *ppc = NULL;
    HRESULT hr = CreateCondition(m_Type, &pClone);
    if (FAILED(hr))
        return hr;
    hr = pClone->SetLeaf(m_pszProperty, m_Op, m_pszValueType, &m_Value, m_pszLocale,
                         m_pPropertyTerm, m_pOperationTerm, m_pValueTerm);
    for (INT i = 0; SUCCEEDED(hr) && i < m_Subs.GetSize(); ++i)
    {
        CComPtr<ICondition> pSub;
        hr = m_Subs[i]->Clone(&pSub);
        if (SUCCEEDED(hr))
            hr = pClone->AddSub(pSub);
    }
    if (FAILED(hr))
    {
        pClone->Release();
        return hr;
    }
    *ppc = pClone;
    return S_OK;
}

static HRESULT
ReturnCondition(CCondition *pCondition, REFIID riid, void **ppv)
{
    HRESULT hr = pCondition->QueryInterface(riid, ppv);
    pCondition->Release();
    return hr;
}

static HRESULT
CreateCompound(CONDITION_TYPE Type, ICondition **ppSubs, ULONG cSubs, CONDITION_CREATION_OPTIONS cco,
               REFIID riid, void **ppv)
{
    CCondition *pCondition;

    if (!ppv)
        return E_POINTER;
    *ppv = NULL;
    if (Type != CT_AND_CONDITION && Type != CT_OR_CONDITION)
        return E_INVALIDARG;
    if (cSubs && !ppSubs)
        return E_INVALIDARG;
    if ((cco & CONDITION_CREATION_SIMPLIFY) && cSubs == 1 && ppSubs[0])
        return ppSubs[0]->QueryInterface(riid, ppv);

    HRESULT hr = CreateCondition(Type, &pCondition);
    if (FAILED(hr))
        return hr;
    for (ULONG i = 0; SUCCEEDED(hr) && i < cSubs; ++i)
        hr = pCondition->AddSub(ppSubs[i]);
    if (FAILED(hr))
    {
        pCondition->Release();
        return hr;
    }
    return ReturnCondition(pCondition, riid, ppv);
}

static HRESULT
CreateLeafCondition(LPCWSTR pszProperty, CONDITION_OPERATION Op, LPCWSTR pszValueType,
                    const PROPVARIANT *pValue, LPCWSTR pszLocale, IRichChunk *pPropertyTerm,
                    IRichChunk *pOperationTerm, IRichChunk *pValueTerm, CONDITION_CREATION_OPTIONS cco,
                    REFIID riid, void **ppv)
{
    CCondition *pCondition;

    if (!ppv)
        return E_POINTER;
    *ppv = NULL;

    if (pValue && pValue->vt == (VT_VECTOR | VT_LPWSTR) &&
        (cco & (CONDITION_CREATION_VECTOR_AND | CONDITION_CREATION_VECTOR_OR)))
    {
        CONDITION_TYPE Type = (cco & CONDITION_CREATION_VECTOR_AND) ? CT_AND_CONDITION : CT_OR_CONDITION;
        HRESULT hr = CreateCondition(Type, &pCondition);
        for (ULONG i = 0; SUCCEEDED(hr) && i < pValue->calpwstr.cElems; ++i)
        {
            PROPVARIANT Element;
            CComPtr<ICondition> pLeaf;
            hr = InitPropVariantFromString(pValue->calpwstr.pElems[i], &Element);
            if (SUCCEEDED(hr))
            {
                hr = CreateLeafCondition(pszProperty, Op, pszValueType, &Element, pszLocale, NULL, NULL, NULL,
                                         CONDITION_CREATION_DEFAULT, IID_PPV_ARG(ICondition, &pLeaf));
                PropVariantClear(&Element);
            }
            if (SUCCEEDED(hr))
                hr = pCondition->AddSub(pLeaf);
        }
        if (FAILED(hr))
        {
            if (pCondition)
                pCondition->Release();
            return hr;
        }
        return ReturnCondition(pCondition, riid, ppv);
    }

    HRESULT hr = CreateCondition(CT_LEAF_CONDITION, &pCondition);
    if (FAILED(hr))
        return hr;
    hr = pCondition->SetLeaf(pszProperty, Op, pszValueType, pValue, pszLocale,
                             pPropertyTerm, pOperationTerm, pValueTerm);
    if (FAILED(hr))
    {
        pCondition->Release();
        return hr;
    }
    return ReturnCondition(pCondition, riid, ppv);
}

static HRESULT
CreateKeyLeaf(REFPROPERTYKEY propkey, CONDITION_OPERATION Op, const PROPVARIANT *pValue, LPCWSTR pszValueType,
              LPCWSTR pszLocale, IRichChunk *pPropertyTerm, IRichChunk *pOperationTerm, IRichChunk *pValueTerm,
              CONDITION_CREATION_OPTIONS cco, REFIID riid, void **ppv)
{
    CComHeapPtr<WCHAR> pszName;

    if (!ppv)
        return E_POINTER;
    *ppv = NULL;
    HRESULT hr = PSGetNameFromPropertyKey(propkey, &pszName);
    if (FAILED(hr))
        return hr;
    return CreateLeafCondition(pszName, Op, pszValueType, pValue, pszLocale, pPropertyTerm,
                               pOperationTerm, pValueTerm, cco, riid, ppv);
}

class CConditionFactory :
    public CComCoClass<CConditionFactory, &CLSID_ConditionFactory>,
    public CComObjectRootEx<CComMultiThreadModelNoCS>,
    public IConditionFactory2
{
public:
    STDMETHOD(MakeNot)(ICondition *pcSub, BOOL fSimplify, ICondition **ppcResult) override
    {
        return CreateNegation(pcSub, fSimplify ? CONDITION_CREATION_SIMPLIFY : CONDITION_CREATION_DEFAULT,
                              IID_PPV_ARG(ICondition, ppcResult));
    }

    STDMETHOD(MakeAndOr)(CONDITION_TYPE ct, IEnumUnknown *peuSubs, BOOL fSimplify, ICondition **ppcResult) override
    {
        CSimpleArray<ICondition *> Subs;
        HRESULT hr = S_OK;

        if (!ppcResult)
            return E_POINTER;
        *ppcResult = NULL;
        if (peuSubs)
        {
            IUnknown *punk;
            while (SUCCEEDED(hr) && peuSubs->Next(1, &punk, NULL) == S_OK)
            {
                ICondition *pSub = NULL;
                hr = punk->QueryInterface(IID_PPV_ARG(ICondition, &pSub));
                punk->Release();
                if (SUCCEEDED(hr) && !Subs.Add(pSub))
                {
                    pSub->Release();
                    hr = E_OUTOFMEMORY;
                }
            }
        }
        if (SUCCEEDED(hr))
            hr = CreateCompound(ct, Subs.GetData(), Subs.GetSize(),
                                fSimplify ? CONDITION_CREATION_SIMPLIFY : CONDITION_CREATION_DEFAULT,
                                IID_PPV_ARG(ICondition, ppcResult));
        for (INT i = 0; i < Subs.GetSize(); ++i)
            Subs[i]->Release();
        return hr;
    }

    STDMETHOD(MakeLeaf)(LPCWSTR pszPropertyName, CONDITION_OPERATION cop, LPCWSTR pszValueType,
                        const PROPVARIANT *ppropvar, IRichChunk *pPropertyNameTerm, IRichChunk *pOperationTerm,
                        IRichChunk *pValueTerm, BOOL fExpand, ICondition **ppcResult) override
    {
        return CreateLeafCondition(pszPropertyName, cop, pszValueType, ppropvar, NULL, pPropertyNameTerm,
                                   pOperationTerm, pValueTerm, CONDITION_CREATION_DEFAULT,
                                   IID_PPV_ARG(ICondition, ppcResult));
    }

    STDMETHOD(Resolve)(ICondition *pc, STRUCTURED_QUERY_RESOLVE_OPTION sqro,
                       const SYSTEMTIME *pstReferenceTime, ICondition **ppcResolved) override
    {
        if (!ppcResolved)
            return E_POINTER;
        *ppcResolved = NULL;
        if (!pc)
            return E_INVALIDARG;
        return pc->Clone(ppcResolved);
    }

    STDMETHOD(CreateTrueFalse)(BOOL fVal, CONDITION_CREATION_OPTIONS cco, REFIID riid, void **ppv) override
    {
        return CreateCompound(fVal ? CT_AND_CONDITION : CT_OR_CONDITION, NULL, 0, cco, riid, ppv);
    }

    STDMETHOD(CreateNegation)(ICondition *pcSub, CONDITION_CREATION_OPTIONS cco, REFIID riid, void **ppv) override
    {
        CONDITION_TYPE SubType;
        CCondition *pCondition;

        if (!ppv)
            return E_POINTER;
        *ppv = NULL;
        if (!pcSub)
            return E_INVALIDARG;
        if ((cco & CONDITION_CREATION_SIMPLIFY) && SUCCEEDED(pcSub->GetConditionType(&SubType)) &&
            SubType == CT_NOT_CONDITION)
        {
            CComPtr<ICondition> pInner;
            if (SUCCEEDED(pcSub->GetSubConditions(IID_PPV_ARG(ICondition, &pInner))))
                return pInner->QueryInterface(riid, ppv);
        }
        HRESULT hr = CreateCondition(CT_NOT_CONDITION, &pCondition);
        if (FAILED(hr))
            return hr;
        hr = pCondition->AddSub(pcSub);
        if (FAILED(hr))
        {
            pCondition->Release();
            return hr;
        }
        return ReturnCondition(pCondition, riid, ppv);
    }

    STDMETHOD(CreateCompoundFromObjectArray)(CONDITION_TYPE ct, IObjectArray *poaSubs, CONDITION_CREATION_OPTIONS cco,
                                             REFIID riid, void **ppv) override
    {
        CSimpleArray<ICondition *> Subs;
        UINT cSubs = 0;
        HRESULT hr = S_OK;

        if (poaSubs)
            hr = poaSubs->GetCount(&cSubs);
        for (UINT i = 0; SUCCEEDED(hr) && i < cSubs; ++i)
        {
            ICondition *pSub = NULL;
            hr = poaSubs->GetAt(i, IID_PPV_ARG(ICondition, &pSub));
            if (SUCCEEDED(hr) && !Subs.Add(pSub))
            {
                pSub->Release();
                hr = E_OUTOFMEMORY;
            }
        }
        if (SUCCEEDED(hr))
            hr = CreateCompound(ct, Subs.GetData(), Subs.GetSize(), cco, riid, ppv);
        for (INT i = 0; i < Subs.GetSize(); ++i)
            Subs[i]->Release();
        return hr;
    }

    STDMETHOD(CreateCompoundFromArray)(CONDITION_TYPE ct, ICondition **ppcondSubs, ULONG cSubs,
                                       CONDITION_CREATION_OPTIONS cco, REFIID riid, void **ppv) override
    {
        return CreateCompound(ct, ppcondSubs, cSubs, cco, riid, ppv);
    }

    STDMETHOD(CreateStringLeaf)(REFPROPERTYKEY propkey, CONDITION_OPERATION cop, LPCWSTR pszValue,
                                LPCWSTR pszLocaleName, CONDITION_CREATION_OPTIONS cco, REFIID riid, void **ppv) override
    {
        PROPVARIANT Value;
        HRESULT hr = InitPropVariantFromString(pszValue ? pszValue : L"", &Value);
        if (FAILED(hr))
            return hr;
        hr = CreateKeyLeaf(propkey, cop, &Value, NULL, pszLocaleName, NULL, NULL, NULL, cco, riid, ppv);
        PropVariantClear(&Value);
        return hr;
    }

    STDMETHOD(CreateIntegerLeaf)(REFPROPERTYKEY propkey, CONDITION_OPERATION cop, INT32 lValue,
                                 CONDITION_CREATION_OPTIONS cco, REFIID riid, void **ppv) override
    {
        PROPVARIANT Value;
        PropVariantInit(&Value);
        Value.vt = VT_I4;
        Value.lVal = lValue;
        return CreateKeyLeaf(propkey, cop, &Value, NULL, NULL, NULL, NULL, NULL, cco, riid, ppv);
    }

    STDMETHOD(CreateBooleanLeaf)(REFPROPERTYKEY propkey, CONDITION_OPERATION cop, BOOL fValue,
                                 CONDITION_CREATION_OPTIONS cco, REFIID riid, void **ppv) override
    {
        PROPVARIANT Value;
        PropVariantInit(&Value);
        Value.vt = VT_BOOL;
        Value.boolVal = fValue ? VARIANT_TRUE : VARIANT_FALSE;
        return CreateKeyLeaf(propkey, cop, &Value, NULL, NULL, NULL, NULL, NULL, cco, riid, ppv);
    }

    STDMETHOD(CreateLeaf)(REFPROPERTYKEY propkey, CONDITION_OPERATION cop, REFPROPVARIANT propvar,
                          LPCWSTR pszSemanticType, LPCWSTR pszLocaleName, IRichChunk *pPropertyNameTerm,
                          IRichChunk *pOperationTerm, IRichChunk *pValueTerm, CONDITION_CREATION_OPTIONS cco,
                          REFIID riid, void **ppv) override
    {
        return CreateKeyLeaf(propkey, cop, &propvar, pszSemanticType, pszLocaleName, pPropertyNameTerm,
                             pOperationTerm, pValueTerm, cco, riid, ppv);
    }

    STDMETHOD(ResolveCondition)(ICondition *pc, STRUCTURED_QUERY_RESOLVE_OPTION sqro,
                                const SYSTEMTIME *pstReferenceTime, REFIID riid, void **ppv) override
    {
        CComPtr<ICondition> pResolved;

        if (!ppv)
            return E_POINTER;
        *ppv = NULL;
        HRESULT hr = Resolve(pc, sqro, pstReferenceTime, &pResolved);
        if (FAILED(hr))
            return hr;
        return pResolved->QueryInterface(riid, ppv);
    }

    DECLARE_NO_REGISTRY()
    DECLARE_NOT_AGGREGATABLE(CConditionFactory)
    DECLARE_PROTECT_FINAL_CONSTRUCT()

    BEGIN_COM_MAP(CConditionFactory)
        COM_INTERFACE_ENTRY_IID(IID_IConditionFactory2, IConditionFactory2)
        COM_INTERFACE_ENTRY_IID(IID_IConditionFactory, IConditionFactory)
    END_COM_MAP()
};

OBJECT_ENTRY_AUTO(CLSID_ConditionFactory, CConditionFactory)

static HRESULT
GetItemProperty(REFPROPERTYKEY Key, LPCWSTR pszPath, const WIN32_FIND_DATAW *pFindData, PROPVARIANT *pValue)
{
    PropVariantInit(pValue);

    if (IsEqualPropertyKey(Key, PKEY_FileName) || IsEqualPropertyKey(Key, PKEY_ItemNameDisplay) ||
        IsEqualPropertyKey(Key, PKEY_ItemName))
    {
        return InitPropVariantFromString(pFindData->cFileName, pValue);
    }
    if (IsEqualPropertyKey(Key, PKEY_FileExtension))
        return InitPropVariantFromString(PathFindExtensionW(pFindData->cFileName), pValue);
    if (IsEqualPropertyKey(Key, PKEY_ItemPathDisplay))
        return InitPropVariantFromString(pszPath, pValue);
    if (IsEqualPropertyKey(Key, PKEY_ItemFolderPathDisplay))
    {
        WCHAR szFolder[MAX_PATH];
        StringCchCopyW(szFolder, _countof(szFolder), pszPath);
        PathRemoveFileSpecW(szFolder);
        return InitPropVariantFromString(szFolder, pValue);
    }
    if (IsEqualPropertyKey(Key, PKEY_Size))
    {
        if (pFindData->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            return S_OK;
        return InitPropVariantFromUInt64(((ULONGLONG)pFindData->nFileSizeHigh << 32) | pFindData->nFileSizeLow, pValue);
    }
    if (IsEqualPropertyKey(Key, PKEY_DateModified))
        return InitPropVariantFromFileTime(&pFindData->ftLastWriteTime, pValue);
    if (IsEqualPropertyKey(Key, PKEY_DateCreated))
        return InitPropVariantFromFileTime(&pFindData->ftCreationTime, pValue);
    if (IsEqualPropertyKey(Key, PKEY_DateAccessed))
        return InitPropVariantFromFileTime(&pFindData->ftLastAccessTime, pValue);
    if (IsEqualPropertyKey(Key, PKEY_FileAttributes))
        return InitPropVariantFromUInt32(pFindData->dwFileAttributes, pValue);

    CComPtr<IShellItem2> pItem;
    CComPtr<IPropertyStore> pStore;
    HRESULT hr = SHCreateItemFromParsingName(pszPath, NULL, IID_PPV_ARG(IShellItem2, &pItem));
    if (SUCCEEDED(hr))
        hr = pItem->GetPropertyStore(GPS_DEFAULT, IID_PPV_ARG(IPropertyStore, &pStore));
    if (FAILED(hr))
        return hr;
    return pStore->GetValue(Key, pValue);
}

static BOOL
MatchWord(LPCWSTR pszText, LPCWSTR pszWord, BOOL bPrefix)
{
    SIZE_T cchWord = wcslen(pszWord);

    while (*pszText)
    {
        while (*pszText && !IsCharAlphaNumericW(*pszText))
            ++pszText;
        LPCWSTR pszStart = pszText;
        while (*pszText && IsCharAlphaNumericW(*pszText))
            ++pszText;
        SIZE_T cch = pszText - pszStart;
        if (cch && cch >= cchWord && !StrCmpNIW(pszStart, pszWord, (INT)cchWord) && (bPrefix || cch == cchWord))
            return TRUE;
    }
    return FALSE;
}

static BOOL
CompareLeaf(CONDITION_OPERATION Op, const PROPVARIANT *pItem, const PROPVARIANT *pCondition)
{
    if (Op == COP_IMPLICIT)
        Op = (pCondition->vt == VT_LPWSTR || pCondition->vt == VT_BSTR) ? COP_WORD_STARTSWITH : COP_EQUAL;

    switch (Op)
    {
        case COP_VALUE_STARTSWITH:
        case COP_VALUE_ENDSWITH:
        case COP_VALUE_CONTAINS:
        case COP_VALUE_NOTCONTAINS:
        case COP_DOSWILDCARDS:
        case COP_WORD_EQUAL:
        case COP_WORD_STARTSWITH:
        {
            CComHeapPtr<WCHAR> pszItem, pszValue;
            if (FAILED(PropVariantToStringAlloc(*pItem, &pszItem)) ||
                FAILED(PropVariantToStringAlloc(*pCondition, &pszValue)))
            {
                return Op == COP_VALUE_NOTCONTAINS;
            }
            SIZE_T cchItem = wcslen(pszItem), cchValue = wcslen(pszValue);
            switch (Op)
            {
                case COP_VALUE_STARTSWITH:
                    return !StrCmpNIW(pszItem, pszValue, (INT)cchValue);
                case COP_VALUE_ENDSWITH:
                    return cchItem >= cchValue && !lstrcmpiW(pszItem + cchItem - cchValue, pszValue);
                case COP_VALUE_CONTAINS:
                    return StrStrIW(pszItem, pszValue) != NULL;
                case COP_VALUE_NOTCONTAINS:
                    return StrStrIW(pszItem, pszValue) == NULL;
                case COP_DOSWILDCARDS:
                    return PathMatchSpecW(pszItem, pszValue);
                case COP_WORD_EQUAL:
                    return MatchWord(pszItem, pszValue, FALSE);
                default:
                    return MatchWord(pszItem, pszValue, TRUE);
            }
        }

        case COP_EQUAL:
        case COP_NOTEQUAL:
        case COP_LESSTHAN:
        case COP_GREATERTHAN:
        case COP_LESSTHANOREQUAL:
        case COP_GREATERTHANOREQUAL:
        {
            PROPVARIANT Converted;
            const PROPVARIANT *pValue = pCondition;
            PropVariantInit(&Converted);
            if (pItem->vt != pCondition->vt && pItem->vt != VT_EMPTY &&
                SUCCEEDED(PropVariantChangeType(&Converted, *pCondition, 0, pItem->vt)))
            {
                pValue = &Converted;
            }
            INT nCompare = PropVariantCompareEx(*pItem, *pValue, PVCU_DEFAULT, PVCF_USESTRCMPI);
            PropVariantClear(&Converted);
            switch (Op)
            {
                case COP_EQUAL: return nCompare == 0;
                case COP_NOTEQUAL: return nCompare != 0;
                case COP_LESSTHAN: return nCompare < 0;
                case COP_GREATERTHAN: return nCompare > 0;
                case COP_LESSTHANOREQUAL: return nCompare <= 0;
                default: return nCompare >= 0;
            }
        }

        default:
            return FALSE;
    }
}

BOOL
SQ_EvaluateCondition(ICondition *pCondition, LPCWSTR pszPath, const WIN32_FIND_DATAW *pFindData)
{
    CONDITION_TYPE Type;

    if (!pCondition || FAILED(pCondition->GetConditionType(&Type)))
        return FALSE;

    switch (Type)
    {
        case CT_AND_CONDITION:
        case CT_OR_CONDITION:
        {
            CComPtr<IEnumUnknown> pEnum;
            IUnknown *punk;
            if (FAILED(pCondition->GetSubConditions(IID_PPV_ARG(IEnumUnknown, &pEnum))))
                return Type == CT_AND_CONDITION;
            while (pEnum->Next(1, &punk, NULL) == S_OK)
            {
                CComPtr<ICondition> pSub;
                BOOL bMatch = SUCCEEDED(punk->QueryInterface(IID_PPV_ARG(ICondition, &pSub))) &&
                              SQ_EvaluateCondition(pSub, pszPath, pFindData);
                punk->Release();
                if (Type == CT_AND_CONDITION && !bMatch)
                    return FALSE;
                if (Type == CT_OR_CONDITION && bMatch)
                    return TRUE;
            }
            return Type == CT_AND_CONDITION;
        }

        case CT_NOT_CONDITION:
        {
            CComPtr<ICondition> pSub;
            if (FAILED(pCondition->GetSubConditions(IID_PPV_ARG(ICondition, &pSub))))
                return FALSE;
            return !SQ_EvaluateCondition(pSub, pszPath, pFindData);
        }

        case CT_LEAF_CONDITION:
        {
            CComHeapPtr<WCHAR> pszProperty;
            CONDITION_OPERATION Op;
            PROPVARIANT Value, Item;
            PROPERTYKEY Key;
            BOOL bMatch = FALSE;

            PropVariantInit(&Value);
            if (FAILED(pCondition->GetComparisonInfo(&pszProperty, &Op, &Value)))
                return FALSE;
            if (pszProperty && SUCCEEDED(PSGetPropertyKeyFromName(pszProperty, &Key)) &&
                SUCCEEDED(GetItemProperty(Key, pszPath, pFindData, &Item)))
            {
                bMatch = CompareLeaf(Op, &Item, &Value);
                PropVariantClear(&Item);
            }
            PropVariantClear(&Value);
            return bMatch;
        }

        default:
            return FALSE;
    }
}
