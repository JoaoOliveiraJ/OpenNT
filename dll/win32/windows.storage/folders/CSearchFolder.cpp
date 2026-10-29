/*
 * PROJECT:     OpenNT Windows Storage
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Search results folder, search folder item factory and search-ms parsing
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif.ing@outlook.com>
 */

#include "precomp.h"
#include "../CSearch.h"

static const CLSID CLSID_SearchResultsFolder =
    { 0xb2952b16, 0x0e07, 0x4e5a, { 0xb9, 0x93, 0x58, 0xc5, 0x2c, 0xb9, 0x4c, 0xae } };

#define SEARCH_ITEM_TYPE      0x7F
#define SEARCH_ITEM_SIGNATURE 0x48435253UL
#define SEARCH_KIND_SPEC      1
#define SEARCH_KIND_RESULT    2

#pragma pack(push, 1)
typedef struct _SEARCHITEM
{
    WORD cb;
    BYTE bType;
    BYTE bKind;
    DWORD dwSignature;
    DWORD cbData;
    BYTE Data[1];
} SEARCHITEM;
#pragma pack(pop)

static PITEMID_CHILD
CreateSearchItem(BYTE bKind, const void *pvData, DWORD cbData)
{
    UINT cbItem = FIELD_OFFSET(SEARCHITEM, Data) + cbData;
    if (cbItem + sizeof(WORD) > 0xFFFF)
        return NULL;
    SEARCHITEM *pItem = (SEARCHITEM *)SHAlloc(cbItem + sizeof(WORD));
    if (!pItem)
        return NULL;
    pItem->cb = (WORD)cbItem;
    pItem->bType = SEARCH_ITEM_TYPE;
    pItem->bKind = bKind;
    pItem->dwSignature = SEARCH_ITEM_SIGNATURE;
    pItem->cbData = cbData;
    CopyMemory(pItem->Data, pvData, cbData);
    *(WORD *)((BYTE *)pItem + cbItem) = 0;
    return (PITEMID_CHILD)pItem;
}

static const SEARCHITEM *
GetSearchItem(PCUIDLIST_RELATIVE pidl, BYTE bKind)
{
    const SEARCHITEM *pItem = (const SEARCHITEM *)pidl;
    if (!pidl || pidl->mkid.cb < FIELD_OFFSET(SEARCHITEM, Data) || pItem->bType != SEARCH_ITEM_TYPE ||
        pItem->bKind != bKind || pItem->dwSignature != SEARCH_ITEM_SIGNATURE ||
        pItem->cbData > (DWORD)(pidl->mkid.cb - FIELD_OFFSET(SEARCHITEM, Data)))
    {
        return NULL;
    }
    return pItem;
}

static PCIDLIST_ABSOLUTE
GetResultTarget(PCUIDLIST_RELATIVE pidl)
{
    const SEARCHITEM *pItem = GetSearchItem(pidl, SEARCH_KIND_RESULT);
    if (!pItem || pItem->cbData < sizeof(WORD))
        return NULL;
    PCIDLIST_ABSOLUTE pidlTarget = (PCIDLIST_ABSOLUTE)pItem->Data;
    if (ILGetSize(pidlTarget) != pItem->cbData)
        return NULL;
    return pidlTarget;
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
ReadString(IStream *pStream, CStringW &Dest)
{
    DWORD cch;
    Dest.Empty();
    HRESULT hr = ReadExact(pStream, &cch, sizeof(cch));
    if (FAILED(hr) || !cch)
        return hr;
    if (cch > 0x8000)
        return E_INVALIDARG;
    LPWSTR psz = Dest.GetBuffer(cch);
    hr = ReadExact(pStream, psz, cch * sizeof(WCHAR));
    if (SUCCEEDED(hr))
        psz[cch - 1] = UNICODE_NULL;
    Dest.ReleaseBuffer();
    return hr;
}

struct SEARCHSPEC
{
    CStringW Name;
    CStringW ParsingName;
    CSimpleArray<CStringW> Scopes;
    CComPtr<ICondition> Condition;

    HRESULT Save(IStream *pStream)
    {
        DWORD dwVersion = 1, cScopes = Scopes.GetSize(), bCondition = Condition != NULL;
        HRESULT hr = pStream->Write(&dwVersion, sizeof(dwVersion), NULL);
        if (SUCCEEDED(hr))
            hr = WriteString(pStream, Name);
        if (SUCCEEDED(hr))
            hr = WriteString(pStream, ParsingName.IsEmpty() ? NULL : (LPCWSTR)ParsingName);
        if (SUCCEEDED(hr))
            hr = pStream->Write(&cScopes, sizeof(cScopes), NULL);
        for (INT i = 0; SUCCEEDED(hr) && i < Scopes.GetSize(); ++i)
            hr = WriteString(pStream, Scopes[i]);
        if (SUCCEEDED(hr))
            hr = pStream->Write(&bCondition, sizeof(bCondition), NULL);
        if (SUCCEEDED(hr) && Condition)
        {
            CComPtr<IPersistStream> pPersist;
            hr = Condition->QueryInterface(IID_PPV_ARG(IPersistStream, &pPersist));
            if (SUCCEEDED(hr))
                hr = OleSaveToStream(pPersist, pStream);
        }
        return hr;
    }

    HRESULT Load(IStream *pStream)
    {
        DWORD dwVersion, cScopes, bCondition;
        HRESULT hr = ReadExact(pStream, &dwVersion, sizeof(dwVersion));
        if (FAILED(hr))
            return hr;
        if (dwVersion != 1)
            return E_INVALIDARG;
        hr = ReadString(pStream, Name);
        if (SUCCEEDED(hr))
            hr = ReadString(pStream, ParsingName);
        if (SUCCEEDED(hr))
            hr = ReadExact(pStream, &cScopes, sizeof(cScopes));
        if (FAILED(hr))
            return hr;
        if (cScopes > 0x400)
            return E_INVALIDARG;
        Scopes.RemoveAll();
        for (DWORD i = 0; i < cScopes; ++i)
        {
            CStringW Scope;
            hr = ReadString(pStream, Scope);
            if (FAILED(hr))
                return hr;
            if (!Scopes.Add(Scope))
                return E_OUTOFMEMORY;
        }
        hr = ReadExact(pStream, &bCondition, sizeof(bCondition));
        if (FAILED(hr))
            return hr;
        Condition.Release();
        if (bCondition)
            hr = OleLoadFromStream(pStream, IID_PPV_ARG(ICondition, &Condition));
        return hr;
    }
};

static HRESULT
CreateSearchIDList(SEARCHSPEC &Spec, PIDLIST_ABSOLUTE *ppidl)
{
    CComPtr<IStream> pStream;
    STATSTG Stat;
    HRESULT hr;

    *ppidl = NULL;
    pStream.Attach(SHCreateMemStream(NULL, 0));
    if (!pStream)
        return E_OUTOFMEMORY;
    hr = Spec.Save(pStream);
    if (FAILED(hr))
        return hr;
    hr = pStream->Stat(&Stat, STATFLAG_NONAME);
    if (FAILED(hr))
        return hr;
    if (Stat.cbSize.QuadPart > 0xF000)
        return E_INVALIDARG;

    DWORD cbData = Stat.cbSize.LowPart;
    CComHeapPtr<BYTE> pData;
    if (!pData.Allocate(cbData ? cbData : 1))
        return E_OUTOFMEMORY;
    LARGE_INTEGER Zero = {};
    hr = pStream->Seek(Zero, STREAM_SEEK_SET, NULL);
    if (SUCCEEDED(hr))
        hr = ReadExact(pStream, (BYTE *)pData, cbData);
    if (FAILED(hr))
        return hr;

    CComHeapPtr<ITEMIDLIST> pidlRoot(_ILCreateGuid(PT_GUID, CLSID_SearchResultsFolder, 0));
    CComHeapPtr<ITEMID_CHILD> pidlSpec(CreateSearchItem(SEARCH_KIND_SPEC, pData, cbData));
    if (!pidlRoot || !pidlSpec)
        return E_OUTOFMEMORY;
    *ppidl = ILCombine(pidlRoot, pidlSpec);
    return *ppidl ? S_OK : E_OUTOFMEMORY;
}

static HRESULT
LoadSearchSpec(PCUIDLIST_RELATIVE pidl, SEARCHSPEC &Spec)
{
    const SEARCHITEM *pItem = GetSearchItem(pidl, SEARCH_KIND_SPEC);
    if (!pItem)
        return E_INVALIDARG;
    CComPtr<IStream> pStream;
    pStream.Attach(SHCreateMemStream(pItem->Data, pItem->cbData));
    if (!pStream)
        return E_OUTOFMEMORY;
    return Spec.Load(pStream);
}

static HRESULT
SetStrRetFromBuffer(LPSTRRET pStrRet, LPCWSTR psz)
{
    pStrRet->uType = STRRET_WSTR;
    return SHStrDupW(psz, &pStrRet->pOleStr);
}

class CSearchFolderEnum :
    public CEnumIDListBase
{
public:
    HRESULT Initialize(SEARCHSPEC *pSpec, SHCONTF grfFlags)
    {
        for (INT i = 0; i < pSpec->Scopes.GetSize(); ++i)
            AddScope(pSpec, pSpec->Scopes[i], grfFlags);
        return S_OK;
    }

    void AddScope(SEARCHSPEC *pSpec, LPCWSTR pszScope, SHCONTF grfFlags)
    {
        CAtlList<CStringW> Pending;
        Pending.AddTail(pszScope);

        while (!Pending.IsEmpty())
        {
            CStringW Directory = Pending.RemoveHead();
            WCHAR szPattern[MAX_PATH];
            WIN32_FIND_DATAW FindData;

            if (FAILED(StringCchCopyW(szPattern, _countof(szPattern), Directory)) || !PathAppendW(szPattern, L"*"))
                continue;
            HANDLE hFind = FindFirstFileExW(szPattern, FindExInfoBasic, &FindData, FindExSearchNameMatch, NULL, 0);
            if (hFind == INVALID_HANDLE_VALUE)
                continue;
            do
            {
                if (!wcscmp(FindData.cFileName, L".") || !wcscmp(FindData.cFileName, L".."))
                    continue;
                if ((FindData.dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) &&
                    !(grfFlags & SHCONTF_INCLUDEHIDDEN))
                {
                    continue;
                }

                WCHAR szPath[MAX_PATH];
                if (FAILED(StringCchCopyW(szPath, _countof(szPath), Directory)) || !PathAppendW(szPath, FindData.cFileName))
                    continue;

                BOOL bFolder = (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                if (bFolder && !(FindData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                    Pending.AddTail(szPath);
                if (!(grfFlags & (bFolder ? SHCONTF_FOLDERS : SHCONTF_NONFOLDERS)))
                    continue;
                if (pSpec->Condition && !SQ_EvaluateCondition(pSpec->Condition, szPath, &FindData))
                    continue;

                CComHeapPtr<ITEMIDLIST> pidlTarget(ILCreateFromPathW(szPath));
                if (!pidlTarget)
                    continue;
                LPITEMIDLIST pidlItem = CreateSearchItem(SEARCH_KIND_RESULT, pidlTarget, ILGetSize(pidlTarget));
                if (pidlItem && !AddToEnumList(pidlItem))
                    SHFree(pidlItem);
            } while (FindNextFileW(hFind, &FindData));
            FindClose(hFind);
        }
    }

    BEGIN_COM_MAP(CSearchFolderEnum)
        COM_INTERFACE_ENTRY_IID(IID_IEnumIDList, IEnumIDList)
    END_COM_MAP()
};

class CSearchFolder :
    public CComCoClass<CSearchFolder, &CLSID_SearchResultsFolder>,
    public CComObjectRootEx<CComMultiThreadModelNoCS>,
    public IShellFolder2,
    public IPersistFolder2
{
private:
    CComHeapPtr<ITEMIDLIST> m_pidlRoot;
    BOOL m_bHasSpec;
    SEARCHSPEC m_Spec;

    HRESULT GetColumnProvider(IShellFolder2 **ppFolder)
    {
        *ppFolder = NULL;
        if (!m_bHasSpec || !m_Spec.Scopes.GetSize())
            return E_FAIL;
        CComHeapPtr<ITEMIDLIST> pidlScope(ILCreateFromPathW(m_Spec.Scopes[0]));
        if (!pidlScope)
            return E_FAIL;
        return SHBindToObject(NULL, pidlScope, NULL, IID_PPV_ARG(IShellFolder2, ppFolder));
    }

    static HRESULT BindTargetParent(PCUIDLIST_RELATIVE pidl, REFIID riid, void **ppv, PCUITEMID_CHILD *ppidlChild)
    {
        PCIDLIST_ABSOLUTE pidlTarget = GetResultTarget(pidl);
        if (!pidlTarget)
            return E_INVALIDARG;
        return SHBindToParent(pidlTarget, riid, ppv, ppidlChild);
    }

public:
    CSearchFolder() : m_bHasSpec(FALSE)
    {
    }

    STDMETHOD(ParseDisplayName)(HWND hwndOwner, LPBC pbc, LPOLESTR lpszDisplayName, ULONG *pchEaten,
                                PIDLIST_RELATIVE *ppidl, ULONG *pdwAttributes) override
    {
        if (ppidl)
            *ppidl = NULL;
        return E_NOTIMPL;
    }

    STDMETHOD(EnumObjects)(HWND hwndOwner, DWORD dwFlags, LPENUMIDLIST *ppEnumIDList) override
    {
        if (!ppEnumIDList)
            return E_POINTER;
        *ppEnumIDList = NULL;
        if (!m_bHasSpec)
            return ShellObjectCreator<CSearchFolderEnum>(IID_PPV_ARG(IEnumIDList, ppEnumIDList));
        return ShellObjectCreatorInit<CSearchFolderEnum>(&m_Spec, (SHCONTF)dwFlags, IID_PPV_ARG(IEnumIDList, ppEnumIDList));
    }

    STDMETHOD(BindToObject)(PCUIDLIST_RELATIVE pidl, LPBC pbcReserved, REFIID riid, LPVOID *ppvOut) override
    {
        if (!ppvOut)
            return E_POINTER;
        *ppvOut = NULL;
        if (!pidl || !pidl->mkid.cb)
            return E_INVALIDARG;

        if (!m_bHasSpec)
        {
            if (!GetSearchItem(pidl, SEARCH_KIND_SPEC))
                return E_INVALIDARG;
            CComHeapPtr<ITEMID_CHILD> pidlFirst((PITEMID_CHILD)ILCloneFirst(pidl));
            CComHeapPtr<ITEMIDLIST> pidlAbsolute(ILCombine(m_pidlRoot, pidlFirst));
            if (!pidlFirst || !pidlAbsolute)
                return E_OUTOFMEMORY;
            CComPtr<IPersistFolder> pPersist;
            HRESULT hr = ShellObjectCreator<CSearchFolder>(IID_PPV_ARG(IPersistFolder, &pPersist));
            if (SUCCEEDED(hr))
                hr = pPersist->Initialize(pidlAbsolute);
            if (FAILED(hr))
                return hr;
            PCUIDLIST_RELATIVE pidlNext = ILGetNext(pidl);
            if (pidlNext && pidlNext->mkid.cb)
            {
                CComPtr<IShellFolder> pFolder;
                hr = pPersist->QueryInterface(IID_PPV_ARG(IShellFolder, &pFolder));
                if (FAILED(hr))
                    return hr;
                return pFolder->BindToObject(pidlNext, pbcReserved, riid, ppvOut);
            }
            return pPersist->QueryInterface(riid, ppvOut);
        }

        PCIDLIST_ABSOLUTE pidlTarget = GetResultTarget(pidl);
        if (!pidlTarget)
            return E_INVALIDARG;
        CComHeapPtr<ITEMIDLIST> pidlFull(ILCombine(pidlTarget, ILGetNext(pidl)));
        if (!pidlFull)
            return E_OUTOFMEMORY;
        return SHBindToObject(NULL, pidlFull, pbcReserved, riid, ppvOut);
    }

    STDMETHOD(BindToStorage)(PCUIDLIST_RELATIVE pidl, LPBC pbcReserved, REFIID riid, LPVOID *ppvOut) override
    {
        if (ppvOut)
            *ppvOut = NULL;
        return E_NOTIMPL;
    }

    STDMETHOD(CompareIDs)(LPARAM lParam, PCUIDLIST_RELATIVE pidl1, PCUIDLIST_RELATIVE pidl2) override
    {
        STRRET sr1, sr2;
        CComHeapPtr<WCHAR> psz1, psz2;
        HRESULT hr;

        if (!pidl1 || !pidl2)
            return E_INVALIDARG;
        hr = GetDisplayNameOf((PCUITEMID_CHILD)pidl1, SHGDN_FORPARSING, &sr1);
        if (SUCCEEDED(hr))
            hr = StrRetToStrW(&sr1, pidl1, &psz1);
        if (SUCCEEDED(hr))
            hr = GetDisplayNameOf((PCUITEMID_CHILD)pidl2, SHGDN_FORPARSING, &sr2);
        if (SUCCEEDED(hr))
            hr = StrRetToStrW(&sr2, pidl2, &psz2);
        if (FAILED(hr))
            return hr;
        INT nResult = lstrcmpiW(psz1, psz2);
        return MAKE_HRESULT(SEVERITY_SUCCESS, 0, (USHORT)(SHORT)(nResult < 0 ? -1 : nResult > 0));
    }

    STDMETHOD(CreateViewObject)(HWND hwndOwner, REFIID riid, LPVOID *ppvOut) override
    {
        if (!ppvOut)
            return E_POINTER;
        *ppvOut = NULL;
        if (IsEqualIID(riid, IID_IShellView))
        {
            SFV_CREATE sfvparams = { sizeof(SFV_CREATE), this };
            return SHCreateShellFolderView(&sfvparams, (IShellView **)ppvOut);
        }
        return E_NOINTERFACE;
    }

    STDMETHOD(GetAttributesOf)(UINT cidl, PCUITEMID_CHILD_ARRAY apidl, DWORD *rgfInOut) override
    {
        if (!rgfInOut)
            return E_POINTER;
        if (cidl && !apidl)
            return E_INVALIDARG;
        if (!cidl)
        {
            *rgfInOut &= SFGAO_FOLDER | SFGAO_HASSUBFOLDER | SFGAO_BROWSABLE;
            return S_OK;
        }

        DWORD dwResult = *rgfInOut;
        for (UINT i = 0; i < cidl; ++i)
        {
            if (!m_bHasSpec)
            {
                if (!GetSearchItem(apidl[i], SEARCH_KIND_SPEC))
                    return E_INVALIDARG;
                dwResult &= SFGAO_FOLDER | SFGAO_HASSUBFOLDER | SFGAO_BROWSABLE;
                continue;
            }
            CComPtr<IShellFolder> pParent;
            PCUITEMID_CHILD pidlChild;
            HRESULT hr = BindTargetParent(apidl[i], IID_PPV_ARG(IShellFolder, &pParent), &pidlChild);
            if (FAILED(hr))
                return hr;
            DWORD dwItem = *rgfInOut;
            hr = pParent->GetAttributesOf(1, &pidlChild, &dwItem);
            if (FAILED(hr))
                return hr;
            dwResult &= dwItem;
        }
        *rgfInOut = dwResult;
        return S_OK;
    }

    STDMETHOD(GetUIObjectOf)(HWND hwndOwner, UINT cidl, PCUITEMID_CHILD_ARRAY apidl, REFIID riid,
                             UINT *prgfInOut, LPVOID *ppvOut) override
    {
        if (!ppvOut)
            return E_POINTER;
        *ppvOut = NULL;
        if (!cidl || !apidl)
            return E_INVALIDARG;

        if (!m_bHasSpec)
        {
            if (cidl == 1 && GetSearchItem(apidl[0], SEARCH_KIND_SPEC) &&
                (IsEqualIID(riid, IID_IExtractIconW) || IsEqualIID(riid, IID_IExtractIconA)))
            {
                CComPtr<IDefaultExtractIconInit> pInit;
                HRESULT hr = SHCreateDefaultExtractIcon(IID_PPV_ARG(IDefaultExtractIconInit, &pInit));
                if (SUCCEEDED(hr))
                    hr = pInit->SetNormalIcon(swShell32Name, -IDI_SHELL_SEARCH);
                if (FAILED(hr))
                    return hr;
                return pInit->QueryInterface(riid, ppvOut);
            }
            return E_NOINTERFACE;
        }

        CComPtr<IShellFolder> pParent;
        CComHeapPtr<ITEMIDLIST> pidlParent;
        CSimpleArray<PCUITEMID_CHILD> Children;
        for (UINT i = 0; i < cidl; ++i)
        {
            PCIDLIST_ABSOLUTE pidlTarget = GetResultTarget(apidl[i]);
            if (!pidlTarget)
                return E_INVALIDARG;
            CComHeapPtr<ITEMIDLIST> pidlThisParent(ILClone(pidlTarget));
            if (!pidlThisParent)
                return E_OUTOFMEMORY;
            ILRemoveLastID(pidlThisParent);
            if (!pidlParent)
            {
                pidlParent.Attach(pidlThisParent.Detach());
                HRESULT hr;
                if (_ILIsDesktop(pidlParent))
                    hr = SHGetDesktopFolder(&pParent);
                else
                    hr = SHBindToObject(NULL, pidlParent, NULL, IID_PPV_ARG(IShellFolder, &pParent));
                if (FAILED(hr))
                    return hr;
            }
            else if (!ILIsEqual(pidlParent, pidlThisParent))
            {
                return E_NOTIMPL;
            }
            if (!Children.Add(ILFindLastID(pidlTarget)))
                return E_OUTOFMEMORY;
        }
        return pParent->GetUIObjectOf(hwndOwner, cidl, Children.GetData(), riid, prgfInOut, ppvOut);
    }

    STDMETHOD(GetDisplayNameOf)(PCUITEMID_CHILD pidl, DWORD dwFlags, LPSTRRET strRet) override
    {
        if (!strRet)
            return E_POINTER;
        if (!pidl)
            return E_INVALIDARG;

        if (!m_bHasSpec)
        {
            SEARCHSPEC Spec;
            HRESULT hr = LoadSearchSpec(pidl, Spec);
            if (FAILED(hr))
                return hr;
            if ((dwFlags & SHGDN_FORPARSING) && !Spec.ParsingName.IsEmpty())
                return SetStrRetFromBuffer(strRet, Spec.ParsingName);
            return SetStrRetFromBuffer(strRet, Spec.Name);
        }

        CComPtr<IShellFolder> pParent;
        PCUITEMID_CHILD pidlChild;
        STRRET srTarget;
        CComHeapPtr<WCHAR> pszName;
        HRESULT hr = BindTargetParent(pidl, IID_PPV_ARG(IShellFolder, &pParent), &pidlChild);
        if (SUCCEEDED(hr))
            hr = pParent->GetDisplayNameOf(pidlChild, dwFlags, &srTarget);
        if (SUCCEEDED(hr))
            hr = StrRetToStrW(&srTarget, pidlChild, &pszName);
        if (FAILED(hr))
            return hr;
        strRet->uType = STRRET_WSTR;
        strRet->pOleStr = pszName.Detach();
        return S_OK;
    }

    STDMETHOD(SetNameOf)(HWND hwndOwner, PCUITEMID_CHILD pidl, LPCOLESTR lpName, DWORD dwFlags,
                         PITEMID_CHILD *pPidlOut) override
    {
        if (pPidlOut)
            *pPidlOut = NULL;
        return E_NOTIMPL;
    }

    STDMETHOD(GetDefaultSearchGUID)(GUID *pguid) override
    {
        return E_NOTIMPL;
    }

    STDMETHOD(EnumSearches)(IEnumExtraSearch **ppenum) override
    {
        if (ppenum)
            *ppenum = NULL;
        return E_NOTIMPL;
    }

    STDMETHOD(GetDefaultColumn)(DWORD dwRes, ULONG *pSort, ULONG *pDisplay) override
    {
        if (!pSort || !pDisplay)
            return E_POINTER;
        *pSort = 0;
        *pDisplay = 0;
        return S_OK;
    }

    STDMETHOD(GetDefaultColumnState)(UINT iColumn, SHCOLSTATEF *pcsFlags) override
    {
        CComPtr<IShellFolder2> pProvider;
        HRESULT hr = GetColumnProvider(&pProvider);
        if (FAILED(hr))
            return hr;
        return pProvider->GetDefaultColumnState(iColumn, pcsFlags);
    }

    STDMETHOD(GetDetailsEx)(PCUITEMID_CHILD pidl, const SHCOLUMNID *pscid, VARIANT *pv) override
    {
        if (!m_bHasSpec)
            return E_NOTIMPL;
        CComPtr<IShellFolder2> pParent;
        PCUITEMID_CHILD pidlChild;
        HRESULT hr = BindTargetParent(pidl, IID_PPV_ARG(IShellFolder2, &pParent), &pidlChild);
        if (FAILED(hr))
            return hr;
        return pParent->GetDetailsEx(pidlChild, pscid, pv);
    }

    STDMETHOD(GetDetailsOf)(PCUITEMID_CHILD pidl, UINT iColumn, SHELLDETAILS *psd) override
    {
        if (!psd)
            return E_POINTER;
        if (!pidl)
        {
            CComPtr<IShellFolder2> pProvider;
            HRESULT hr = GetColumnProvider(&pProvider);
            if (FAILED(hr))
                return hr;
            return pProvider->GetDetailsOf(NULL, iColumn, psd);
        }
        if (!m_bHasSpec)
            return E_NOTIMPL;

        CComPtr<IShellFolder2> pParent;
        PCUITEMID_CHILD pidlChild;
        CComHeapPtr<WCHAR> pszText;
        HRESULT hr = BindTargetParent(pidl, IID_PPV_ARG(IShellFolder2, &pParent), &pidlChild);
        if (SUCCEEDED(hr))
            hr = pParent->GetDetailsOf(pidlChild, iColumn, psd);
        if (SUCCEEDED(hr))
            hr = StrRetToStrW(&psd->str, pidlChild, &pszText);
        if (FAILED(hr))
            return hr;
        psd->str.uType = STRRET_WSTR;
        psd->str.pOleStr = pszText.Detach();
        return S_OK;
    }

    STDMETHOD(MapColumnToSCID)(UINT column, SHCOLUMNID *pscid) override
    {
        CComPtr<IShellFolder2> pProvider;
        HRESULT hr = GetColumnProvider(&pProvider);
        if (FAILED(hr))
            return hr;
        return pProvider->MapColumnToSCID(column, pscid);
    }

    STDMETHOD(GetClassID)(CLSID *lpClassId) override
    {
        if (!lpClassId)
            return E_POINTER;
        *lpClassId = CLSID_SearchResultsFolder;
        return S_OK;
    }

    STDMETHOD(Initialize)(PCIDLIST_ABSOLUTE pidl) override
    {
        if (!pidl)
            return E_INVALIDARG;
        m_pidlRoot.Free();
        m_pidlRoot.Attach(ILClone(pidl));
        if (!m_pidlRoot)
            return E_OUTOFMEMORY;
        m_bHasSpec = SUCCEEDED(LoadSearchSpec(ILFindLastID(pidl), m_Spec));
        return S_OK;
    }

    STDMETHOD(GetCurFolder)(PIDLIST_ABSOLUTE *pidl) override
    {
        if (!pidl)
            return E_POINTER;
        *pidl = ILClone(m_pidlRoot);
        return *pidl ? S_OK : E_FAIL;
    }

    DECLARE_NO_REGISTRY()
    DECLARE_NOT_AGGREGATABLE(CSearchFolder)
    DECLARE_PROTECT_FINAL_CONSTRUCT()

    BEGIN_COM_MAP(CSearchFolder)
        COM_INTERFACE_ENTRY_IID(IID_IShellFolder2, IShellFolder2)
        COM_INTERFACE_ENTRY_IID(IID_IShellFolder, IShellFolder)
        COM_INTERFACE_ENTRY_IID(IID_IPersistFolder2, IPersistFolder2)
        COM_INTERFACE_ENTRY_IID(IID_IPersistFolder, IPersistFolder)
        COM_INTERFACE_ENTRY_IID(IID_IPersist, IPersist)
    END_COM_MAP()
};

OBJECT_ENTRY_AUTO(CLSID_SearchResultsFolder, CSearchFolder)

class CSearchFolderItemFactory :
    public CComCoClass<CSearchFolderItemFactory, &CLSID_SearchFolderItemFactory>,
    public CComObjectRootEx<CComMultiThreadModelNoCS>,
    public ISearchFolderItemFactory
{
private:
    SEARCHSPEC m_Spec;

public:
    STDMETHOD(SetDisplayName)(LPCWSTR pszDisplayName) override
    {
        if (!pszDisplayName)
            return E_INVALIDARG;
        m_Spec.Name = pszDisplayName;
        return S_OK;
    }

    STDMETHOD(SetFolderTypeID)(FOLDERTYPEID ftid) override
    {
        return E_NOTIMPL;
    }

    STDMETHOD(SetFolderLogicalViewMode)(FOLDERLOGICALVIEWMODE flvm) override
    {
        return E_NOTIMPL;
    }

    STDMETHOD(SetIconSize)(int iIconSize) override
    {
        return E_NOTIMPL;
    }

    STDMETHOD(SetVisibleColumns)(UINT cVisibleColumns, const PROPERTYKEY *rgKey) override
    {
        return E_NOTIMPL;
    }

    STDMETHOD(SetSortColumns)(UINT cSortColumns, SORTCOLUMN *rgSortColumns) override
    {
        return E_NOTIMPL;
    }

    STDMETHOD(SetGroupColumn)(REFPROPERTYKEY keyGroup) override
    {
        return E_NOTIMPL;
    }

    STDMETHOD(SetStacks)(UINT cStackKeys, PROPERTYKEY *rgStackKeys) override
    {
        return E_NOTIMPL;
    }

    STDMETHOD(SetScope)(IShellItemArray *psiaScope) override
    {
        DWORD cItems = 0;
        CSimpleArray<CStringW> Scopes;

        if (!psiaScope)
            return E_INVALIDARG;
        HRESULT hr = psiaScope->GetCount(&cItems);
        for (DWORD i = 0; SUCCEEDED(hr) && i < cItems; ++i)
        {
            CComPtr<IShellItem> pItem;
            CComHeapPtr<WCHAR> pszPath;
            hr = psiaScope->GetItemAt(i, &pItem);
            if (SUCCEEDED(hr) && SUCCEEDED(pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszPath)))
            {
                CStringW Scope(pszPath);
                if (!Scopes.Add(Scope))
                    hr = E_OUTOFMEMORY;
            }
        }
        if (FAILED(hr))
            return hr;
        if (!Scopes.GetSize())
            return E_INVALIDARG;
        m_Spec.Scopes.RemoveAll();
        for (INT i = 0; i < Scopes.GetSize(); ++i)
        {
            if (!m_Spec.Scopes.Add(Scopes[i]))
                return E_OUTOFMEMORY;
        }
        return S_OK;
    }

    STDMETHOD(SetCondition)(ICondition *pCondition) override
    {
        m_Spec.Condition = pCondition;
        return S_OK;
    }

    STDMETHOD(GetShellItem)(REFIID riid, void **ppv) override
    {
        CComHeapPtr<ITEMIDLIST> pidl;

        if (!ppv)
            return E_POINTER;
        *ppv = NULL;
        HRESULT hr = GetIDList(&pidl);
        if (FAILED(hr))
            return hr;
        return SHCreateItemFromIDList(pidl, riid, ppv);
    }

    STDMETHOD(GetIDList)(PIDLIST_ABSOLUTE *ppidl) override
    {
        if (!ppidl)
            return E_POINTER;
        *ppidl = NULL;
        if (!m_Spec.Scopes.GetSize())
            return E_UNEXPECTED;
        return CreateSearchIDList(m_Spec, ppidl);
    }

    DECLARE_NO_REGISTRY()
    DECLARE_NOT_AGGREGATABLE(CSearchFolderItemFactory)
    DECLARE_PROTECT_FINAL_CONSTRUCT()

    BEGIN_COM_MAP(CSearchFolderItemFactory)
        COM_INTERFACE_ENTRY_IID(IID_ISearchFolderItemFactory, ISearchFolderItemFactory)
    END_COM_MAP()
};

OBJECT_ENTRY_AUTO(CLSID_SearchFolderItemFactory, CSearchFolderItemFactory)
