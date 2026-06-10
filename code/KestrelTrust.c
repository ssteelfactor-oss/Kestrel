/*
 * KestrelTrust.c — v0.7  domain / forest trust posture audit
 *
 * Enumerates trustedDomain objects from the directory and decodes their
 * security posture. Pure ADSI/LDAP read against a DC — fits Kestrel's
 * invariants cleanly (read-only, DC/directory only, ordinary domain user,
 * no evasion) with no footprint disclaimer, unlike KestrelPolicy (SYSVOL/SMB).
 *
 * Like KestrelPolicy / KestrelRoast this is an audit scan: it returns findings;
 * it does not feed KestrelBuildGraph.
 *
 * Primary finding: missing SID filtering on an inbound external trust — the
 * classic sIDHistory-injection surface. Within-forest trusts deliberately
 * carry no SID filtering (the forest is the boundary) and are not flagged.
 */

#include "Kestrel.h"

/* trustAttributes bits (MS-ADTS 6.1.6.7.9) */
#define TA_NON_TRANSITIVE             0x00000001
#define TA_UPLEVEL_ONLY               0x00000002
#define TA_QUARANTINED_DOMAIN         0x00000004   /* SID filtering enabled */
#define TA_FOREST_TRANSITIVE          0x00000008
#define TA_CROSS_ORGANIZATION         0x00000010
#define TA_WITHIN_FOREST              0x00000020
#define TA_TREAT_AS_EXTERNAL          0x00000040
#define TA_USES_RC4_ENCRYPTION        0x00000080
#define TA_CROSS_ORG_ENABLE_TGT_DELEG 0x00000400
#define TA_PIM_TRUST                  0x00000800

/* ════════════════════════════════════════════════════════════════════════════
 * Local helpers
 * ════════════════════════════════════════════════════════════════════════════ */

static VOID TrustNote(_Inout_ KESTREL_TRUST_FINDING *pF, _In_z_ LPCWSTR pwszNote)
{
    if (pF->wszRisk[0])
        (void)StringCchCatW(pF->wszRisk, ARRAYSIZE(pF->wszRisk), L"; ");
    (void)StringCchCatW(pF->wszRisk, ARRAYSIZE(pF->wszRisk), pwszNote);
}

static VOID TrustClassify(_Inout_ KESTREL_TRUST_FINDING *pF)
{
    DWORD a = pF->dwAttributes;
    BOOL  bInbound = (pF->Direction == TRUST_DIR_INBOUND ||
                      pF->Direction == TRUST_DIR_BIDIRECTIONAL);

    pF->bWithinForest     = (a & TA_WITHIN_FOREST) != 0;
    pF->bForestTransitive = (a & TA_FOREST_TRANSITIVE) != 0;
    pF->bTransitive       = (a & TA_NON_TRANSITIVE) == 0;
    pF->bSidFiltering     = (a & TA_QUARANTINED_DOMAIN) != 0;
    pF->bRC4              = (a & TA_USES_RC4_ENCRYPTION) != 0;
    pF->bTgtDelegEnabled  = (a & TA_CROSS_ORG_ENABLE_TGT_DELEG) != 0;
    pF->bTreatAsExternal  = (a & TA_TREAT_AS_EXTERNAL) != 0;

    pF->wszRisk[0] = L'\0';

    /* Conservative posture notes. Within-forest excluded from the SID-filter
     * check — otherwise every intra-forest trust false-positives. */
    if (bInbound && !pF->bWithinForest && !pF->bSidFiltering)
        TrustNote(pF, L"no SID filtering (sIDHistory surface)");
    if (pF->bTreatAsExternal)
        TrustNote(pF, L"forest trust treated as external");
    if (pF->bTgtDelegEnabled)
        TrustNote(pF, L"TGT delegation across trust");
    if (pF->bRC4)
        TrustNote(pF, L"RC4 encryption");
}

static BOOL TrustColInt(_In_ IDirectorySearch *pSearch, _In_ ADS_SEARCH_HANDLE hRow,
                        _In_z_ LPWSTR pwszAttr, _Out_ long *plOut)
{
    ADS_SEARCH_COLUMN col;
    *plOut = 0;
    if (IDirectorySearch_GetColumn(pSearch, hRow, pwszAttr, &col) != S_OK)
        return FALSE;
    if (col.dwADsType == ADSTYPE_INTEGER && col.dwNumValues > 0)
        *plOut = (long)col.pADsValues[0].Integer;
    (void)IDirectorySearch_FreeColumn(pSearch, &col);
    return TRUE;
}

static BOOL TrustColStr(_In_ IDirectorySearch *pSearch, _In_ ADS_SEARCH_HANDLE hRow,
                        _In_z_ LPWSTR pwszAttr, _Out_writes_z_(cch) LPWSTR pwszOut, size_t cch)
{
    ADS_SEARCH_COLUMN col;
    pwszOut[0] = L'\0';
    if (IDirectorySearch_GetColumn(pSearch, hRow, pwszAttr, &col) != S_OK)
        return FALSE;
    if ((col.dwADsType == ADSTYPE_CASE_IGNORE_STRING ||
         col.dwADsType == ADSTYPE_CASE_EXACT_STRING  ||
         col.dwADsType == ADSTYPE_DN_STRING          ||
         col.dwADsType == ADSTYPE_PRINTABLE_STRING) && col.dwNumValues > 0)
        (void)StringCchCopyW(pwszOut, cch, col.pADsValues[0].CaseIgnoreString);
    (void)IDirectorySearch_FreeColumn(pSearch, &col);
    return TRUE;
}

static BOOL TrustColSid(_In_ IDirectorySearch *pSearch, _In_ ADS_SEARCH_HANDLE hRow,
                        _In_z_ LPWSTR pwszAttr, _Out_writes_z_(cch) LPWSTR pwszOut, size_t cch)
{
    ADS_SEARCH_COLUMN col;
    pwszOut[0] = L'\0';
    if (IDirectorySearch_GetColumn(pSearch, hRow, pwszAttr, &col) != S_OK)
        return FALSE;
    if (col.dwADsType == ADSTYPE_OCTET_STRING && col.dwNumValues > 0) {
        LPWSTR pwszSid = NULL;
        PSID   pSid    = (PSID)col.pADsValues[0].OctetString.lpValue;
        if (IsValidSid(pSid) && ConvertSidToStringSidW(pSid, &pwszSid) && pwszSid) {
            (void)StringCchCopyW(pwszOut, cch, pwszSid);
            LocalFree(pwszSid);
        }
    }
    (void)IDirectorySearch_FreeColumn(pSearch, &col);
    return TRUE;
}

static HRESULT TrustAppend(_Inout_ KESTREL_TRUST_SCAN_RESULT *pResult,
                           _In_ const KESTREL_TRUST_FINDING *pF)
{
    if (pResult->cFindings >= pResult->cCapacity) {
        DWORD  cNew = pResult->cCapacity ? pResult->cCapacity * 2 : 8;
        SIZE_T cb   = (SIZE_T)cNew * sizeof(KESTREL_TRUST_FINDING);
        KESTREL_TRUST_FINDING *p;

        if (pResult->rgFindings)
            p = (KESTREL_TRUST_FINDING *)HeapReAlloc(GetProcessHeap(),
                    HEAP_ZERO_MEMORY, pResult->rgFindings, cb);
        else
            p = (KESTREL_TRUST_FINDING *)HeapAlloc(GetProcessHeap(),
                    HEAP_ZERO_MEMORY, cb);
        if (!p)
            return E_OUTOFMEMORY;

        pResult->rgFindings = p;
        pResult->cCapacity  = cNew;
    }
    pResult->rgFindings[pResult->cFindings++] = *pF;
    return S_OK;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Public API
 * ════════════════════════════════════════════════════════════════════════════ */

VOID KestrelFreeTrustScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_TRUST_SCAN_RESULT *pResult)
{
    if (!pResult)
        return;
    if (pResult->rgFindings)
        HeapFree(GetProcessHeap(), 0, pResult->rgFindings);
    HeapFree(GetProcessHeap(), 0, pResult);
}

_Must_inspect_result_
HRESULT KestrelRunTrustScan(
    _In_z_   LPCWSTR                     pwszDomainNC,
    _Outptr_ KESTREL_TRUST_SCAN_RESULT **ppResult)
{
    HRESULT                    hr      = S_OK;
    IDirectorySearch          *pSearch = NULL;
    ADS_SEARCH_HANDLE          hRow    = NULL;
    KESTREL_TRUST_SCAN_RESULT *pResult = NULL;
    ADS_SEARCHPREF_INFO        pref;
    WCHAR                      wszPath[600];

    static LPWSTR rgAttrs[] = {
        (LPWSTR)L"trustPartner",    (LPWSTR)L"flatName",
        (LPWSTR)L"trustDirection",  (LPWSTR)L"trustType",
        (LPWSTR)L"trustAttributes", (LPWSTR)L"securityIdentifier"
    };
    const DWORD cAttrs = (DWORD)ARRAYSIZE(rgAttrs);

    if (!ppResult || !pwszDomainNC)
        return E_INVALIDARG;
    *ppResult = NULL;

    pResult = (KESTREL_TRUST_SCAN_RESULT *)HeapAlloc(GetProcessHeap(),
                  HEAP_ZERO_MEMORY, sizeof(*pResult));
    if (!pResult)
        return E_OUTOFMEMORY;

    hr = StringCchPrintfW(wszPath, ARRAYSIZE(wszPath), L"LDAP://%s", pwszDomainNC);
    if (FAILED(hr))
        goto cleanup;

    KTRACE(L"Trust: binding %s", wszPath);

    hr = ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pSearch);
    if (FAILED(hr)) {
        KTRACE(L"Trust: ADsGetObject failed 0x%08lX", hr);
        goto cleanup;
    }

    pref.dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    pref.vValue.dwType  = ADSTYPE_INTEGER;
    pref.vValue.Integer = ADS_SCOPE_SUBTREE;
    (void)IDirectorySearch_SetSearchPreference(pSearch, &pref, 1);

    hr = IDirectorySearch_ExecuteSearch(pSearch,
            (LPWSTR)L"(objectClass=trustedDomain)", rgAttrs, cAttrs, &hRow);
    if (FAILED(hr)) {
        KTRACE(L"Trust: ExecuteSearch failed 0x%08lX", hr);
        goto cleanup;
    }

    hr = IDirectorySearch_GetFirstRow(pSearch, hRow);
    while (hr == S_OK) {
        KESTREL_TRUST_FINDING f;
        long lDir = 0, lType = 0, lAttr = 0;

        ZeroMemory(&f, sizeof(f));

        TrustColStr(pSearch, hRow, (LPWSTR)L"trustPartner",
                    f.wszPartner, ARRAYSIZE(f.wszPartner));
        TrustColStr(pSearch, hRow, (LPWSTR)L"flatName",
                    f.wszFlatName, ARRAYSIZE(f.wszFlatName));
        TrustColInt(pSearch, hRow, (LPWSTR)L"trustDirection",  &lDir);
        TrustColInt(pSearch, hRow, (LPWSTR)L"trustType",       &lType);
        TrustColInt(pSearch, hRow, (LPWSTR)L"trustAttributes", &lAttr);
        TrustColSid(pSearch, hRow, (LPWSTR)L"securityIdentifier",
                    f.wszSid, ARRAYSIZE(f.wszSid));

        f.Direction    = (KESTREL_TRUST_DIRECTION)lDir;
        f.Type         = (KESTREL_TRUST_TYPE)lType;
        f.dwAttributes = (DWORD)lAttr;
        TrustClassify(&f);

        pResult->cObjectsScanned++;
        if (f.Direction == TRUST_DIR_INBOUND ||
            f.Direction == TRUST_DIR_BIDIRECTIONAL)
            pResult->cInbound++;
        if (f.wszRisk[0])
            pResult->cRisky++;

        hr = TrustAppend(pResult, &f);
        if (FAILED(hr))
            goto cleanup;

        hr = IDirectorySearch_GetNextRow(pSearch, hRow);
    }
    if (hr == S_ADS_NOMORE_ROWS)
        hr = S_OK;

    KTRACE(L"Trust: %lu object(s), %lu inbound, %lu risky",
           pResult->cObjectsScanned, pResult->cInbound, pResult->cRisky);

cleanup:
    if (pSearch) {
        if (hRow)
            (void)IDirectorySearch_CloseSearchHandle(pSearch, hRow);
        IDirectorySearch_Release(pSearch);
    }
    if (SUCCEEDED(hr)) {
        *ppResult = pResult;
    } else {
        KestrelFreeTrustScanResult(pResult);
    }
    return hr;
}
