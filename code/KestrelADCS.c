/*
 * KestrelADCS.c — v0.7  AD Certificate Services posture audit
 *
 * Passive, read-only enumeration of certificate templates and enrollment
 * services from the Configuration NC. Decodes the well-known ESC misconfig
 * classes that are observable purely over LDAP/ADSI as an ordinary user:
 *
 *   ESC1  enrollee-supplies-subject + client-auth EKU + low-priv enroll,
 *         no manager approval, no enrollment-agent co-sign
 *   ESC2  Any-Purpose (or no) EKU + low-priv enroll
 *   ESC3  Certificate-Request-Agent EKU + low-priv enroll
 *   ESC4  template object writable by a broad principal
 *   ESC5  CA / enrollment-service object writable by a broad principal
 *   ESC9  NO_SECURITY_EXTENSION on an authentication-capable template
 *
 * Out of passive-LDAP scope (noted, not detected here):
 *   ESC6  EDITF_ATTRIBUTESUBJECTALTNAME2 — CA registry flag, not in LDAP
 *   ESC7  CA role ACL (ManageCA / ManageCertificates)
 *   ESC8  HTTP/RPC web-enrollment endpoint (needs probing, not directory)
 *
 * Like the other audit scans this prints its own table and returns findings;
 * it does not feed KestrelBuildGraph. ADCS lives under
 *   CN=Public Key Services,CN=Services,<ConfigNC>
 * so the scan takes the Configuration naming context.
 */

#include "../include/Kestrel.h"

/* ── Control-access right GUIDs ─────────────────────────────────────────────── */
static const GUID GUID_ENROLL =
    { 0x0e10c968, 0x78fb, 0x11d2, { 0x90, 0xd4, 0x00, 0xc0, 0x4f, 0x79, 0xdc, 0x55 } };
static const GUID GUID_AUTOENROLL =
    { 0xa05b8cc2, 0x17bc, 0x4802, { 0xa7, 0x10, 0xe7, 0xc1, 0x5a, 0xb8, 0x66, 0xa2 } };

/* ── EKU OIDs ──────────────────────────────────────────────────────────────── */
#define EKU_CLIENT_AUTH      L"1.3.6.1.5.5.7.3.2"
#define EKU_SMARTCARD_LOGON  L"1.3.6.1.4.1.311.20.2.2"
#define EKU_PKINIT_CLIENT    L"1.3.6.1.5.2.3.4"
#define EKU_ENROLL_AGENT     L"1.3.6.1.4.1.311.20.2.1"
#define EKU_ANY_PURPOSE      L"2.5.29.37.0"

/* ── Template flag bits (MS-CRTD) ──────────────────────────────────────────── */
#define CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT  0x00000001  /* msPKI-Certificate-Name-Flag */
#define CT_FLAG_PEND_ALL_REQUESTS          0x00000002  /* msPKI-Enrollment-Flag        */
#define CT_FLAG_NO_SECURITY_EXTENSION      0x00080000  /* msPKI-Enrollment-Flag (ESC9) */

/* ════════════════════════════════════════════════════════════════════════════
 * Published-template name set (template cn's enabled on any CA)
 * ════════════════════════════════════════════════════════════════════════════ */

typedef struct _ADCS_NAME { WCHAR wsz[256]; } ADCS_NAME;

typedef struct _ADCS_PUBSET {
    ADCS_NAME *rg;
    DWORD      c;
    DWORD      cap;
} ADCS_PUBSET;

static void _PubAdd(_Inout_ ADCS_PUBSET *pSet, _In_z_ LPCWSTR pwsz)
{
    for (DWORD i = 0; i < pSet->c; i++)
        if (_wcsicmp(pSet->rg[i].wsz, pwsz) == 0)
            return;

    if (pSet->c >= pSet->cap) {
        DWORD cNew = pSet->cap ? pSet->cap * 2 : 16;
        ADCS_NAME *p = pSet->rg
            ? (ADCS_NAME *)HeapReAlloc(GetProcessHeap(), 0, pSet->rg, (SIZE_T)cNew * sizeof(ADCS_NAME))
            : (ADCS_NAME *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)cNew * sizeof(ADCS_NAME));
        if (!p) return;
        pSet->rg = p;
        pSet->cap = cNew;
    }
    StringCchCopyW(pSet->rg[pSet->c].wsz, ARRAYSIZE(pSet->rg[pSet->c].wsz), pwsz);
    pSet->c++;
}

static BOOL _PubHas(_In_ const ADCS_PUBSET *pSet, _In_z_ LPCWSTR pwsz)
{
    for (DWORD i = 0; i < pSet->c; i++)
        if (_wcsicmp(pSet->rg[i].wsz, pwsz) == 0)
            return TRUE;
    return FALSE;
}

static void _PubFree(_Inout_ ADCS_PUBSET *pSet)
{
    if (pSet->rg) HeapFree(GetProcessHeap(), 0, pSet->rg);
    pSet->rg = NULL; pSet->c = 0; pSet->cap = 0;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Column readers
 * ════════════════════════════════════════════════════════════════════════════ */

static BOOL _AdcsColStr(_In_ IDirectorySearch *pSearch, _In_ ADS_SEARCH_HANDLE hRow,
                        _In_z_ LPWSTR pwszAttr, _Out_writes_z_(cch) LPWSTR pwszOut, size_t cch)
{
    ADS_SEARCH_COLUMN col;
    pwszOut[0] = L'\0';
    if (pSearch->lpVtbl->GetColumn(pSearch, hRow, pwszAttr, &col) != S_OK)
        return FALSE;
    if (col.pADsValues && col.dwNumValues > 0 &&
        (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING ||
         col.dwADsType == ADSTYPE_CASE_EXACT_STRING  ||
         col.dwADsType == ADSTYPE_DN_STRING          ||
         col.dwADsType == ADSTYPE_PRINTABLE_STRING))
        StringCchCopyW(pwszOut, cch, col.pADsValues[0].CaseIgnoreString);
    pSearch->lpVtbl->FreeColumn(pSearch, &col);
    return TRUE;
}

static BOOL _AdcsColInt(_In_ IDirectorySearch *pSearch, _In_ ADS_SEARCH_HANDLE hRow,
                        _In_z_ LPWSTR pwszAttr, _Out_ DWORD *pdwOut)
{
    ADS_SEARCH_COLUMN col;
    *pdwOut = 0;
    if (pSearch->lpVtbl->GetColumn(pSearch, hRow, pwszAttr, &col) != S_OK)
        return FALSE;
    if (col.dwADsType == ADSTYPE_INTEGER && col.pADsValues && col.dwNumValues > 0)
        *pdwOut = (DWORD)col.pADsValues[0].Integer;
    pSearch->lpVtbl->FreeColumn(pSearch, &col);
    return TRUE;
}

/* Classify pKIExtendedKeyUsage (multi-valued). */
static void _AdcsClassifyEku(_In_ IDirectorySearch *pSearch, _In_ ADS_SEARCH_HANDLE hRow,
                             _Out_ BOOL *pbAuth, _Out_ BOOL *pbAny, _Out_ BOOL *pbAgent)
{
    ADS_SEARCH_COLUMN col;
    *pbAuth = FALSE; *pbAny = FALSE; *pbAgent = FALSE;

    if (pSearch->lpVtbl->GetColumn(pSearch, hRow,
            (LPWSTR)L"pKIExtendedKeyUsage", &col) != S_OK) {
        /* No EKU attribute at all ⇒ usable for any purpose. */
        *pbAny = TRUE;
        return;
    }

    if (col.dwNumValues == 0 || !col.pADsValues) {
        *pbAny = TRUE;
    } else {
        for (DWORD i = 0; i < col.dwNumValues; i++) {
            LPCWSTR oid = col.pADsValues[i].CaseIgnoreString;
            if (!oid) continue;
            if (_wcsicmp(oid, EKU_CLIENT_AUTH)     == 0 ||
                _wcsicmp(oid, EKU_SMARTCARD_LOGON) == 0 ||
                _wcsicmp(oid, EKU_PKINIT_CLIENT)   == 0)
                *pbAuth = TRUE;
            if (_wcsicmp(oid, EKU_ANY_PURPOSE)     == 0)
                *pbAny = TRUE;
            if (_wcsicmp(oid, EKU_ENROLL_AGENT)    == 0)
                *pbAgent = TRUE;
        }
    }
    pSearch->lpVtbl->FreeColumn(pSearch, &col);
}

/* ════════════════════════════════════════════════════════════════════════════
 * Security descriptor / DACL inspection
 * ════════════════════════════════════════════════════════════════════════════ */

static BOOL _AdcsSidIsBroad(_In_ PSID pSid)
{
    BOOL   bBroad = FALSE;
    LPWSTR pwsz   = NULL;

    if (pSid && IsValidSid(pSid) && ConvertSidToStringSidW(pSid, &pwsz) && pwsz) {
        size_t len = wcslen(pwsz);
        if (_wcsicmp(pwsz, L"S-1-1-0")      == 0 ||   /* Everyone            */
            _wcsicmp(pwsz, L"S-1-5-11")     == 0 ||   /* Authenticated Users */
            _wcsicmp(pwsz, L"S-1-5-32-545") == 0)     /* BUILTIN\Users       */
            bBroad = TRUE;
        else if (len > 4 &&
                 (_wcsicmp(pwsz + len - 4, L"-513") == 0 ||   /* Domain Users     */
                  _wcsicmp(pwsz + len - 4, L"-515") == 0))    /* Domain Computers */
            bBroad = TRUE;
        LocalFree(pwsz);
    }
    return bBroad;
}

/* Returns a heap copy of the object's self-relative SD (caller HeapFrees), or NULL. */
static PSECURITY_DESCRIPTOR _AdcsGetSd(_In_ IDirectorySearch *pSearch,
                                       _In_ ADS_SEARCH_HANDLE hRow)
{
    ADS_SEARCH_COLUMN   col;
    PSECURITY_DESCRIPTOR pSD = NULL;
    LPBYTE pRaw = NULL;
    DWORD  cb   = 0;

    if (pSearch->lpVtbl->GetColumn(pSearch, hRow,
            (LPWSTR)L"nTSecurityDescriptor", &col) != S_OK)
        return NULL;

    if (col.pADsValues && col.dwNumValues > 0) {
        if (col.dwADsType == ADSTYPE_NT_SECURITY_DESCRIPTOR) {
            pRaw = col.pADsValues[0].SecurityDescriptor.lpValue;
            cb   = col.pADsValues[0].SecurityDescriptor.dwLength;
        } else if (col.dwADsType == ADSTYPE_OCTET_STRING) {
            pRaw = col.pADsValues[0].OctetString.lpValue;
            cb   = col.pADsValues[0].OctetString.dwLength;
        }
    }

    if (pRaw && cb > 0) {
        pSD = HeapAlloc(GetProcessHeap(), 0, cb);
        if (pSD) {
            memcpy(pSD, pRaw, cb);
            if (!IsValidSecurityDescriptor(pSD)) {
                HeapFree(GetProcessHeap(), 0, pSD);
                pSD = NULL;
            }
        }
    }
    pSearch->lpVtbl->FreeColumn(pSearch, &col);
    return pSD;
}

/* Walk the DACL: set bEnroll if a broad principal holds the Certificate-Enrollment
   control-access right (or GenericAll/all-extended), bWrite if a broad principal
   holds a write-class right. Captures the first triggering enroll SID. */
static void _AdcsWalkDacl(_In_ PSECURITY_DESCRIPTOR pSD,
                          _Out_ BOOL *pbEnroll, _Out_ BOOL *pbWrite,
                          _Out_writes_z_(cch) LPWSTR pwszTrigger, size_t cch)
{
    BOOL bPresent = FALSE, bDefaulted = FALSE;
    PACL pDacl = NULL;

    *pbEnroll = FALSE; *pbWrite = FALSE; pwszTrigger[0] = L'\0';

    if (!GetSecurityDescriptorDacl(pSD, &bPresent, &pDacl, &bDefaulted) ||
        !bPresent || !pDacl)
        return;

    for (WORD i = 0; i < pDacl->AceCount; i++) {
        PVOID       pAceRaw = NULL;
        PACE_HEADER pHdr;
        ACCESS_MASK mask    = 0;
        PSID        pSid    = NULL;
        const GUID *pObjType = NULL;

        if (!GetAce(pDacl, i, &pAceRaw))
            continue;
        pHdr = (PACE_HEADER)pAceRaw;

        if (pHdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE *p = (ACCESS_ALLOWED_ACE *)pAceRaw;
            mask = p->Mask;
            pSid = (PSID)&p->SidStart;
        } else if (pHdr->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE) {
            ACCESS_ALLOWED_OBJECT_ACE *p = (ACCESS_ALLOWED_OBJECT_ACE *)pAceRaw;
            BYTE *pAfter = (BYTE *)&p->ObjectType;
            mask = p->Mask;
            if (p->Flags & ACE_OBJECT_TYPE_PRESENT) {
                pObjType = &p->ObjectType;
                pAfter  += sizeof(GUID);
            }
            if (p->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)
                pAfter  += sizeof(GUID);
            pSid = (PSID)pAfter;
        } else {
            continue;   /* DENY / AUDIT — not a capability grant */
        }

        if (!_AdcsSidIsBroad(pSid))
            continue;

        if (mask & ADS_RIGHT_GENERIC_ALL) {
            if (!*pbEnroll) {
                *pbEnroll = TRUE;
                LPWSTR s = NULL;
                if (ConvertSidToStringSidW(pSid, &s) && s) {
                    StringCchCopyW(pwszTrigger, cch, s); LocalFree(s);
                }
            }
            *pbWrite = TRUE;
        }
        if (mask & (ADS_RIGHT_WRITE_DAC | ADS_RIGHT_WRITE_OWNER |
                    ADS_RIGHT_GENERIC_WRITE | ADS_RIGHT_DS_WRITE_PROP))
            *pbWrite = TRUE;
        if (mask & ADS_RIGHT_DS_CONTROL_ACCESS) {
            if (!pObjType ||
                IsEqualGUID(pObjType, &GUID_ENROLL) ||
                IsEqualGUID(pObjType, &GUID_AUTOENROLL)) {
                if (!*pbEnroll) {
                    *pbEnroll = TRUE;
                    LPWSTR s = NULL;
                    if (ConvertSidToStringSidW(pSid, &s) && s) {
                        StringCchCopyW(pwszTrigger, cch, s); LocalFree(s);
                    }
                }
            }
        }
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * Finding management
 * ════════════════════════════════════════════════════════════════════════════ */

static void _AdcsNote(_Inout_ KESTREL_ADCS_FINDING *pF, _In_z_ LPCWSTR pwsz)
{
    if (pF->wszRisk[0])
        StringCchCatW(pF->wszRisk, ARRAYSIZE(pF->wszRisk), L"; ");
    StringCchCatW(pF->wszRisk, ARRAYSIZE(pF->wszRisk), pwsz);
}

static HRESULT _AdcsAppend(_Inout_ KESTREL_ADCS_SCAN_RESULT *pResult,
                           _In_ const KESTREL_ADCS_FINDING *pF)
{
    if (pResult->cFindings >= pResult->cCapacity) {
        DWORD  cNew = pResult->cCapacity ? pResult->cCapacity * 2 : 8;
        SIZE_T cb   = (SIZE_T)cNew * sizeof(KESTREL_ADCS_FINDING);
        KESTREL_ADCS_FINDING *p = pResult->rgFindings
            ? (KESTREL_ADCS_FINDING *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pResult->rgFindings, cb)
            : (KESTREL_ADCS_FINDING *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb);
        if (!p) return E_OUTOFMEMORY;
        pResult->rgFindings = p;
        pResult->cCapacity  = cNew;
    }
    pResult->rgFindings[pResult->cFindings++] = *pF;
    return S_OK;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Passes
 * ════════════════════════════════════════════════════════════════════════════ */

/* Pass 1 — enrollment services: collect published template names, flag ESC5. */
static HRESULT _AdcsScanCAs(_In_ IDirectorySearch *pSearch,
                            _Inout_ ADCS_PUBSET *pPub,
                            _Inout_ KESTREL_ADCS_SCAN_RESULT *pResult)
{
    HRESULT           hr;
    ADS_SEARCH_HANDLE hRow = NULL;
    static LPWSTR rgAttrs[] = {
        L"cn", L"dNSHostName", L"certificateTemplates", L"nTSecurityDescriptor"
    };

    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
            (LPWSTR)L"(objectClass=pKIEnrollmentService)",
            rgAttrs, (DWORD)ARRAYSIZE(rgAttrs), &hRow);
    if (FAILED(hr)) return hr;

    for (;;) {
        KESTREL_ADCS_FINDING f;
        ADS_SEARCH_COLUMN    col;
        PSECURITY_DESCRIPTOR pSD;
        BOOL bEnroll = FALSE, bWrite = FALSE;
        WCHAR wszTrig[128] = { 0 };

        hr = pSearch->lpVtbl->GetNextRow(pSearch, hRow);
        if (hr == S_ADS_NOMORE_ROWS) { hr = S_OK; break; }
        if (FAILED(hr)) break;

        ZeroMemory(&f, sizeof(f));
        StringCchCopyW(f.wszKind, ARRAYSIZE(f.wszKind), L"ca");
        _AdcsColStr(pSearch, hRow, (LPWSTR)L"cn", f.wszName, ARRAYSIZE(f.wszName));
        _AdcsColStr(pSearch, hRow, (LPWSTR)L"dNSHostName",
                    f.wszDisplayName, ARRAYSIZE(f.wszDisplayName));

        /* certificateTemplates (multi) → published set */
        if (pSearch->lpVtbl->GetColumn(pSearch, hRow,
                (LPWSTR)L"certificateTemplates", &col) == S_OK) {
            for (DWORD i = 0; i < col.dwNumValues; i++)
                if (col.pADsValues[i].CaseIgnoreString)
                    _PubAdd(pPub, col.pADsValues[i].CaseIgnoreString);
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }

        /* ESC5 — broad write on the CA object */
        pSD = _AdcsGetSd(pSearch, hRow);
        if (pSD) {
            _AdcsWalkDacl(pSD, &bEnroll, &bWrite, wszTrig, ARRAYSIZE(wszTrig));
            HeapFree(GetProcessHeap(), 0, pSD);
        }
        if (bWrite) {
            f.bESC5 = TRUE;
            StringCchCopyW(f.wszLowPrivSid, ARRAYSIZE(f.wszLowPrivSid), wszTrig);
            _AdcsNote(&f, L"ESC5: CA object writable by broad principal");
            pResult->cVulnerable++;
            hr = _AdcsAppend(pResult, &f);
            if (FAILED(hr)) break;
        }
    }

    pSearch->lpVtbl->CloseSearchHandle(pSearch, hRow);
    return hr;
}

/* Pass 2 — certificate templates: ESC1/2/3/4/9. */
static HRESULT _AdcsScanTemplates(_In_ IDirectorySearch *pSearch,
                                  _In_ const ADCS_PUBSET *pPub,
                                  _Inout_ KESTREL_ADCS_SCAN_RESULT *pResult)
{
    HRESULT           hr;
    ADS_SEARCH_HANDLE hRow = NULL;
    static LPWSTR rgAttrs[] = {
        L"cn", L"displayName",
        L"msPKI-Certificate-Name-Flag", L"msPKI-Enrollment-Flag",
        L"msPKI-RA-Signature", L"pKIExtendedKeyUsage", L"nTSecurityDescriptor"
    };

    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
            (LPWSTR)L"(objectClass=pKICertificateTemplate)",
            rgAttrs, (DWORD)ARRAYSIZE(rgAttrs), &hRow);
    if (FAILED(hr)) return hr;

    for (;;) {
        KESTREL_ADCS_FINDING f;
        PSECURITY_DESCRIPTOR pSD;
        DWORD dwNameFlag = 0, dwEnrollFlag = 0, dwRaSig = 0;
        BOOL  bAuth = FALSE, bAny = FALSE, bAgent = FALSE;
        BOOL  bEnroll = FALSE, bWrite = FALSE;
        BOOL  bApproval, bAnyEsc = FALSE;
        WCHAR wszTrig[128] = { 0 };

        hr = pSearch->lpVtbl->GetNextRow(pSearch, hRow);
        if (hr == S_ADS_NOMORE_ROWS) { hr = S_OK; break; }
        if (FAILED(hr)) break;

        pResult->cTemplates++;

        ZeroMemory(&f, sizeof(f));
        StringCchCopyW(f.wszKind, ARRAYSIZE(f.wszKind), L"template");
        _AdcsColStr(pSearch, hRow, (LPWSTR)L"cn", f.wszName, ARRAYSIZE(f.wszName));
        _AdcsColStr(pSearch, hRow, (LPWSTR)L"displayName",
                    f.wszDisplayName, ARRAYSIZE(f.wszDisplayName));
        _AdcsColInt(pSearch, hRow, (LPWSTR)L"msPKI-Certificate-Name-Flag", &dwNameFlag);
        _AdcsColInt(pSearch, hRow, (LPWSTR)L"msPKI-Enrollment-Flag",       &dwEnrollFlag);
        _AdcsColInt(pSearch, hRow, (LPWSTR)L"msPKI-RA-Signature",          &dwRaSig);
        _AdcsClassifyEku(pSearch, hRow, &bAuth, &bAny, &bAgent);

        pSD = _AdcsGetSd(pSearch, hRow);
        if (pSD) {
            _AdcsWalkDacl(pSD, &bEnroll, &bWrite, wszTrig, ARRAYSIZE(wszTrig));
            HeapFree(GetProcessHeap(), 0, pSD);
        }

        bApproval        = (dwEnrollFlag & CT_FLAG_PEND_ALL_REQUESTS) != 0;
        f.bPublished     = _PubHas(pPub, f.wszName);
        f.bLowPrivEnroll = bEnroll;
        if (bEnroll)
            StringCchCopyW(f.wszLowPrivSid, ARRAYSIZE(f.wszLowPrivSid), wszTrig);

        /* ESC1 — requester names the subject (incl. SAN) on an auth template,
                  enrollable by a broad principal, no approval, no co-sign. */
        if ((dwNameFlag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) &&
            bAuth && bEnroll && !bApproval && dwRaSig == 0) {
            f.bESC1 = TRUE; bAnyEsc = TRUE;
            _AdcsNote(&f, L"ESC1: enrollee-supplies-subject + auth EKU + low-priv enroll");
        }

        /* ESC2 — Any-Purpose / no EKU, broad enroll, no approval/co-sign. */
        if (bAny && bEnroll && !bApproval && dwRaSig == 0) {
            f.bESC2 = TRUE; bAnyEsc = TRUE;
            _AdcsNote(&f, L"ESC2: Any-Purpose (or no) EKU + low-priv enroll");
        }

        /* ESC3 — Certificate-Request-Agent template enrollable by broad principal. */
        if (bAgent && bEnroll) {
            f.bESC3 = TRUE; bAnyEsc = TRUE;
            _AdcsNote(&f, L"ESC3: enrollment-agent EKU + low-priv enroll");
        }

        /* ESC4 — template object writable by a broad principal. */
        if (bWrite) {
            f.bESC4 = TRUE; bAnyEsc = TRUE;
            _AdcsNote(&f, L"ESC4: template writable by broad principal");
        }

        /* ESC9 — security extension suppressed on an authentication template. */
        if ((dwEnrollFlag & CT_FLAG_NO_SECURITY_EXTENSION) && bAuth) {
            f.bESC9 = TRUE; bAnyEsc = TRUE;
            _AdcsNote(&f, L"ESC9: NO_SECURITY_EXTENSION on auth template");
        }

        if (!bAnyEsc)
            continue;

        if (!f.bPublished)
            _AdcsNote(&f, L"(not published by any CA)");

        pResult->cVulnerable++;
        hr = _AdcsAppend(pResult, &f);
        if (FAILED(hr)) break;
    }

    pSearch->lpVtbl->CloseSearchHandle(pSearch, hRow);
    return hr;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Output
 * ════════════════════════════════════════════════════════════════════════════ */

static void _AdcsEscList(_In_ const KESTREL_ADCS_FINDING *pF,
                         _Out_writes_z_(cch) LPWSTR pwszOut, size_t cch)
{
    pwszOut[0] = L'\0';
    if (pF->bESC1) StringCchCatW(pwszOut, cch, L"ESC1 ");
    if (pF->bESC2) StringCchCatW(pwszOut, cch, L"ESC2 ");
    if (pF->bESC3) StringCchCatW(pwszOut, cch, L"ESC3 ");
    if (pF->bESC4) StringCchCatW(pwszOut, cch, L"ESC4 ");
    if (pF->bESC5) StringCchCatW(pwszOut, cch, L"ESC5 ");
    if (pF->bESC9) StringCchCatW(pwszOut, cch, L"ESC9 ");
}

static void _AdcsPrint(_In_ const KESTREL_ADCS_SCAN_RESULT *pResult)
{
    wprintf(L"\n  ADCS: %lu template(s) examined  |  %lu finding(s)\n",
            pResult->cTemplates, pResult->cVulnerable);

    if (pResult->cFindings == 0) {
        wprintf(L"\n  [*] No ESC1-5/9 misconfigurations detected.\n\n");
        return;
    }

    wprintf(L"\n  %-30s  %-9s  %-22s  %-4s  %s\n",
            L"Name", L"Kind", L"ESC", L"Pub", L"Detail");
    wprintf(L"  ───────────────────────────────────────────────────────────────"
            L"────────────────────────────────────\n");

    for (DWORD i = 0; i < pResult->cFindings; i++) {
        const KESTREL_ADCS_FINDING *pF = &pResult->rgFindings[i];
        WCHAR wszEsc[32];
        _AdcsEscList(pF, wszEsc, ARRAYSIZE(wszEsc));
        wprintf(L"  %-30s  %-9s  %-22s  %-4s  %s\n",
                pF->wszName[0] ? pF->wszName : L"?",
                pF->wszKind,
                wszEsc,
                (_wcsicmp(pF->wszKind, L"ca") == 0) ? L"-"
                    : (pF->bPublished ? L"yes" : L"no"),
                pF->wszRisk[0] ? pF->wszRisk : L"-");
    }
    wprintf(L"\n");
}

/* ════════════════════════════════════════════════════════════════════════════
 * Public API
 * ════════════════════════════════════════════════════════════════════════════ */

VOID KestrelFreeADCSScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_ADCS_SCAN_RESULT *pResult)
{
    if (!pResult)
        return;
    if (pResult->rgFindings)
        HeapFree(GetProcessHeap(), 0, pResult->rgFindings);
    HeapFree(GetProcessHeap(), 0, pResult);
}

_Must_inspect_result_
HRESULT KestrelRunADCSScan(
    _In_z_   LPCWSTR                    pwszConfigNC,
    _Outptr_ KESTREL_ADCS_SCAN_RESULT **ppResult)
{
    HRESULT                   hr      = S_OK;
    IDirectorySearch         *pSearch = NULL;
    KESTREL_ADCS_SCAN_RESULT *pResult = NULL;
    ADCS_PUBSET               pub     = { 0 };
    ADS_SEARCHPREF_INFO       prefs[2];
    WCHAR                     wszPath[700];

    if (!ppResult || !pwszConfigNC)
        return E_INVALIDARG;
    *ppResult = NULL;

    pResult = (KESTREL_ADCS_SCAN_RESULT *)HeapAlloc(GetProcessHeap(),
                  HEAP_ZERO_MEMORY, sizeof(*pResult));
    if (!pResult)
        return E_OUTOFMEMORY;

    hr = StringCchPrintfW(wszPath, ARRAYSIZE(wszPath),
            L"LDAP://CN=Public Key Services,CN=Services,%s", pwszConfigNC);
    if (FAILED(hr))
        goto Cleanup;

    KTRACE(L"ADCS: binding %s", wszPath);

    hr = ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pSearch);
    if (FAILED(hr)) {
        /* No Public Key Services container ⇒ ADCS not deployed. Not an error. */
        KTRACE(L"ADCS: no PKI container (0x%08lX) — ADCS not present", hr);
        wprintf(L"\n  [*] AD CS not deployed in this forest.\n\n");
        hr = S_OK;
        goto Cleanup;
    }

    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref   = ADS_SEARCHPREF_SECURITY_MASK;
    prefs[1].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = ADS_SECURITY_INFO_DACL;   /* DACL only — no SeSecurityPrivilege */
    pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 2);

    /* CAs first (publishes the template set, flags ESC5), then templates. */
    hr = _AdcsScanCAs(pSearch, &pub, pResult);
    if (FAILED(hr)) { KTRACE(L"ADCS: CA pass failed 0x%08lX", hr); goto Cleanup; }

    hr = _AdcsScanTemplates(pSearch, &pub, pResult);
    if (FAILED(hr)) { KTRACE(L"ADCS: template pass failed 0x%08lX", hr); goto Cleanup; }

    KTRACE(L"ADCS: %lu templates, %lu findings", pResult->cTemplates, pResult->cVulnerable);

Cleanup:
    _PubFree(&pub);
    if (pSearch)
        pSearch->lpVtbl->Release(pSearch);
    if (SUCCEEDED(hr)) {
        _AdcsPrint(pResult);
        *ppResult = pResult;
    } else {
        KestrelFreeADCSScanResult(pResult);
    }
    return hr;
}
