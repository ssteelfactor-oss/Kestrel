/*
 * KestrelTrust.c — v0.7  domain / forest trust posture audit
 *
 * Enumerates trustedDomain objects from the directory and decodes their
 * security posture. Pure ADSI/LDAP read against a DC — fits Kestrel's
 * invariants cleanly (read-only, DC/directory only, ordinary domain user,
 * no evasion) with no footprint disclaimer, unlike KestrelPolicy (SYSVOL/SMB).
 *
 * Like KestrelRoast / KestrelGMSA this is an audit scan: it prints its own
 * console table and returns findings; it does not feed KestrelBuildGraph.
 *
 * Primary finding: missing SID filtering on an inbound external trust — the
 * classic sIDHistory-injection surface. Within-forest trusts deliberately
 * carry no SID filtering (the forest is the boundary) and are not flagged.
 */

#include "../include/Kestrel.h"

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
 * Internal helpers
 * ════════════════════════════════════════════════════════════════════════════ */

static LPCWSTR _TrustDirName(_In_ KESTREL_TRUST_DIRECTION d)
{
    switch (d) {
    case TRUST_DIR_DISABLED:      return L"disabled";
    case TRUST_DIR_INBOUND:       return L"inbound";
    case TRUST_DIR_OUTBOUND:      return L"outbound";
    case TRUST_DIR_BIDIRECTIONAL: return L"bidirectional";
    default:                      return L"?";
    }
}

static LPCWSTR _TrustTypeName(_In_ KESTREL_TRUST_TYPE t)
{
    switch (t) {
    case TRUST_TYPE_DOWNLEVEL: return L"downlevel(NT4)";
    case TRUST_TYPE_UPLEVEL:   return L"uplevel(AD)";
    case TRUST_TYPE_MIT:       return L"MIT-realm";
    case TRUST_TYPE_DCE:       return L"DCE";
    default:                   return L"?";
    }
}

static VOID _TrustNote(_Inout_ KESTREL_TRUST_FINDING *pF, _In_z_ LPCWSTR pwszNote)
{
    if (pF->wszRisk[0])
        StringCchCatW(pF->wszRisk, ARRAYSIZE(pF->wszRisk), L"; ");
    StringCchCatW(pF->wszRisk, ARRAYSIZE(pF->wszRisk), pwszNote);
}

static VOID _TrustClassify(_Inout_ KESTREL_TRUST_FINDING *pF)
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

    /* Within-forest excluded from the SID-filter check — otherwise every
     * intra-forest trust false-positives (the forest is the boundary). */
    if (bInbound && !pF->bWithinForest && !pF->bSidFiltering)
        _TrustNote(pF, L"no SID filtering (sIDHistory surface)");
    if (pF->bTreatAsExternal)
        _TrustNote(pF, L"forest trust treated as external");
    if (pF->bTgtDelegEnabled)
        _TrustNote(pF, L"TGT delegation across trust");
    if (pF->bRC4)
        _TrustNote(pF, L"RC4 encryption");
}

static BOOL _TrustColInt(_In_ IDirectorySearch *pSearch, _In_ ADS_SEARCH_HANDLE hRow,
                         _In_z_ LPWSTR pwszAttr, _Out_ long *plOut)
{
    ADS_SEARCH_COLUMN col;
    *plOut = 0;
    if (pSearch->lpVtbl->GetColumn(pSearch, hRow, pwszAttr, &col) != S_OK)
        return FALSE;
    if (col.dwADsType == ADSTYPE_INTEGER && col.pADsValues && col.dwNumValues > 0)
        *plOut = (long)col.pADsValues[0].Integer;
    pSearch->lpVtbl->FreeColumn(pSearch, &col);
    return TRUE;
}

static BOOL _TrustColStr(_In_ IDirectorySearch *pSearch, _In_ ADS_SEARCH_HANDLE hRow,
                         _In_z_ LPWSTR pwszAttr, _Out_writes_z_(cch) LPWSTR pwszOut, size_t cch)
{
    ADS_SEARCH_COLUMN col;
    pwszOut[0] = L'\0';
    if (pSearch->lpVtbl->GetColumn(pSearch, hRow, pwszAttr, &col) != S_OK)
        return FALSE;
    if ((col.dwADsType == ADSTYPE_CASE_IGNORE_STRING ||
         col.dwADsType == ADSTYPE_CASE_EXACT_STRING  ||
         col.dwADsType == ADSTYPE_DN_STRING          ||
         col.dwADsType == ADSTYPE_PRINTABLE_STRING) &&
        col.pADsValues && col.dwNumValues > 0 && col.pADsValues[0].CaseIgnoreString)
        StringCchCopyW(pwszOut, cch, col.pADsValues[0].CaseIgnoreString);
    pSearch->lpVtbl->FreeColumn(pSearch, &col);
    return TRUE;
}

static BOOL _TrustColSid(_In_ IDirectorySearch *pSearch, _In_ ADS_SEARCH_HANDLE hRow,
                         _In_z_ LPWSTR pwszAttr, _Out_writes_z_(cch) LPWSTR pwszOut, size_t cch)
{
    ADS_SEARCH_COLUMN col;
    pwszOut[0] = L'\0';
    if (pSearch->lpVtbl->GetColumn(pSearch, hRow, pwszAttr, &col) != S_OK)
        return FALSE;
    if (col.dwADsType == ADSTYPE_OCTET_STRING && col.pADsValues && col.dwNumValues > 0) {
        LPWSTR pwszSid = NULL;
        PSID   pSid    = (PSID)col.pADsValues[0].OctetString.lpValue;
        if (pSid && IsValidSid(pSid) && ConvertSidToStringSidW(pSid, &pwszSid) && pwszSid) {
            StringCchCopyW(pwszOut, cch, pwszSid);
            LocalFree(pwszSid);
        }
    }
    pSearch->lpVtbl->FreeColumn(pSearch, &col);
    return TRUE;
}

static HRESULT _TrustAppend(_Inout_ KESTREL_TRUST_SCAN_RESULT *pResult,
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

static VOID _TrustPrint(_In_ const KESTREL_TRUST_SCAN_RESULT *pResult)
{
    wprintf(L"\n  Trusts: %lu object(s)  |  inbound: %lu  |  risky: %lu\n",
            pResult->cObjectsScanned, pResult->cInbound, pResult->cRisky);

    if (pResult->cFindings == 0) {
        wprintf(L"\n  [*] No trustedDomain objects "
                L"(single-domain / no external trusts).\n\n");
        return;
    }

    wprintf(L"\n  %-32s  %-13s  %-15s  %-10s  %s\n",
            L"Partner", L"Direction", L"Type", L"Attr", L"Risk");
    wprintf(L"  ─────────────────────────────────────────────────────────"
            L"──────────────────────────────────────────\n");

    for (DWORD i = 0; i < pResult->cFindings; i++) {
        const KESTREL_TRUST_FINDING *pF = &pResult->rgFindings[i];
        wprintf(L"  %-32s  %-13s  %-15s  0x%08lX  %s\n",
                pF->wszPartner[0]    ? pF->wszPartner : L"?",
                _TrustDirName(pF->Direction),
                _TrustTypeName(pF->Type),
                pF->dwAttributes,
                pF->wszRisk[0] ? pF->wszRisk : L"-");
    }
    wprintf(L"\n");
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
        L"trustPartner",    L"flatName",
        L"trustDirection",  L"trustType",
        L"trustAttributes", L"securityIdentifier"
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
        goto Cleanup;

    KTRACE(L"Trust: binding %s", wszPath);

    hr = ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pSearch);
    if (FAILED(hr)) {
        wprintf(L"  [!] KestrelRunTrustScan: ADsGetObject failed 0x%08X\n", hr);
        goto Cleanup;
    }

    pref.dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    pref.vValue.dwType  = ADSTYPE_INTEGER;
    pref.vValue.Integer = ADS_SCOPE_SUBTREE;
    pSearch->lpVtbl->SetSearchPreference(pSearch, &pref, 1);

    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
            L"(objectClass=trustedDomain)", rgAttrs, cAttrs, &hRow);
    if (FAILED(hr)) {
        wprintf(L"  [!] KestrelRunTrustScan: ExecuteSearch failed 0x%08X\n", hr);
        goto Cleanup;
    }

    for (;;) {
        KESTREL_TRUST_FINDING f;
        long lDir = 0, lType = 0, lAttr = 0;

        hr = pSearch->lpVtbl->GetNextRow(pSearch, hRow);
        if (hr == S_ADS_NOMORE_ROWS) { hr = S_OK; break; }
        if (FAILED(hr))              {              break; }

        ZeroMemory(&f, sizeof(f));

        _TrustColStr(pSearch, hRow, L"trustPartner",  f.wszPartner,  ARRAYSIZE(f.wszPartner));
        _TrustColStr(pSearch, hRow, L"flatName",      f.wszFlatName, ARRAYSIZE(f.wszFlatName));
        _TrustColInt(pSearch, hRow, L"trustDirection",  &lDir);
        _TrustColInt(pSearch, hRow, L"trustType",       &lType);
        _TrustColInt(pSearch, hRow, L"trustAttributes", &lAttr);
        _TrustColSid(pSearch, hRow, L"securityIdentifier", f.wszSid, ARRAYSIZE(f.wszSid));

        f.Direction    = (KESTREL_TRUST_DIRECTION)lDir;
        f.Type         = (KESTREL_TRUST_TYPE)lType;
        f.dwAttributes = (DWORD)lAttr;
        _TrustClassify(&f);

        pResult->cObjectsScanned++;
        if (f.Direction == TRUST_DIR_INBOUND ||
            f.Direction == TRUST_DIR_BIDIRECTIONAL)
            pResult->cInbound++;
        if (f.wszRisk[0])
            pResult->cRisky++;

        hr = _TrustAppend(pResult, &f);
        if (FAILED(hr))
            goto Cleanup;
    }

    KTRACE(L"Trust: %lu object(s), %lu inbound, %lu risky",
           pResult->cObjectsScanned, pResult->cInbound, pResult->cRisky);

Cleanup:
    if (pSearch) {
        if (hRow)
            pSearch->lpVtbl->CloseSearchHandle(pSearch, hRow);
        pSearch->lpVtbl->Release(pSearch);
    }
    if (SUCCEEDED(hr)) {
        _TrustPrint(pResult);
        *ppResult = pResult;
    } else {
        KestrelFreeTrustScanResult(pResult);
    }
    return hr;
}
