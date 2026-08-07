# Detection backlog & research notes

Private-in-public knowledge base: candidate detections for future Kestrel
versions, with the public sources that motivate them. Not a commitment — a
research queue. Each entry is only promoted to the README roadmap once it has
concrete, stable indicators (not a moving CVE target) and fits the invariants:
read-only, ordinary domain user, on-prem only, no network call to a service, no
active test of a DC.

Rule of thumb for every entry below: *can this be read from the directory /
SYSVOL as existing state, or would confirming it require sending a crafted /
active request?* Only the former belongs in Kestrel.

---

## 1. Identity-confusion via invisible / homoglyph characters in object names

**Status:** waiting for stable indicators.
**Source:** Semperis (Shai Laron), "Identity Crisis", Black Hat USA 2026 —
KerberLoss (CVE-2026-25177) and ResetNightmare (CVE-2026-27912).

The CVEs themselves are runtime logic flaws in DC-side Kerberos/LDAP processing
(a low-priv user reaches Domain Admin by causing "identity confusion"). Detecting
whether a DC is *vulnerable* would require an active, crafted request — out of
scope, that is the exploit itself.

What IS passively readable: KerberLoss leans on unfilterable / invisible Unicode
characters inside object names (sAMAccountName, SPN, DN). So the durable Kestrel
angle is not "detect this CVE" but a general check:

- Scan object names for anomalous Unicode — zero-width space (U+200B),
  right-to-left override (U+202E), other zero-width / bidi controls, and
  homoglyphs (e.g. Cyrillic "о"/"а" in an otherwise-Latin "Administrator").
- Such a name is either a footprint of exploitation or fertile ground for it,
  and homoglyph impersonation of privileged names is a known problem few audit.

This is broader and more durable than the two CVEs. Hold until the full IOC set
(exact character classes) settles — the article is very fresh.

## 2. dMSA / BadSuccessor (Server 2025)

**Status:** candidate, genuinely new.
**Source:** delegated Managed Service Accounts (Server 2025); BadSuccessor class
(2025). Also seen implemented in adhammer (icedracon).

Delegated MSA attributes are readable from AD. Passive precondition detection
(who can abuse dMSA succession to inherit privileges) fits the philosophy. The
only truly novel item from the adhammer cross-check — worth its own design pass.

## 3. Cross-check against PingCastle-class coverage (adhammer)

**Status:** routine gap-check, low novelty.
**Source:** icedracon/adhammer README (its passive audit = PingCastle-class).

Verify Kestrel isn't missing standard checks from the common pool:
- `dSHeuristics` — anonymous LDAP bind + other security-relevant flags (one
  attribute on the Configuration NC; cheap if absent).
- Pre-Windows 2000 Compatible Access group membership (legacy anonymous read).
- `GptTmpl.inf` depth in SYSVOL — LM/NTLMv1, LDAP/SMB signing, NoLMHash,
  Netlogon sealing. Confirm how deep the current `--policy` parse goes.
- AD CS ESC13 (issuance-policy → group link) — consider adding to the ESC series.

Take only the *coverage* ideas; adhammer's offensive stack is the opposite
philosophy and out of bounds.

## 4. MITRE ATT&CK mapping on findings

**Status:** candidate, defensive metadata.
**Source:** adhammer maps every finding to a technique (T1558.003, T1003.006…).

Add a MITRE technique tag to Kestrel findings (a metadata field alongside
severity / remediation). Blue-team friendly, fits the prioritized-findings
summary. Pure metadata — no mechanism borrowed.

## 5. AD CS ESC1 remediation wording — KB5014754 does NOT fully mitigate

**Status:** fix existing wording (not a new detection).
**Source:** 0xmaz (Mohamed Alzhrani), July 2026 — CMC/addExtensions path issues a
client-auth cert with no szOID_NTDS_CA_SECURITY_EXT (no requester SID), bypassing
KB5014754 strong-mapping enforcement. Microsoft: "Not a Vulnerability" / by design.

Kestrel already detects ESC1-shaped templates (ENROLLEE_SUPPLIES_SUBJECT +
client-auth EKU) passively from the Config NC — the right signal. Action: if any
ESC1 finding/remediation implies "KB5014754 mitigates this," rewrite it. Correct
message: the template itself is the exposure — fix the template (remove
ENROLLEE_SUPPLIES_SUBJECT / restrict enrollment); the patch does not cover the
CMC path. Detection mechanism unchanged.

---

## Service-posture veins (v1.1 stack direction)

Tracked separately as the "services" layer (Exchange first, in progress):
Exchange · SCCM · SQL · DNS/ADIDNS. Plus adjacent veins surfaced in design:
orphaned/archaeology (dead service objects with live dangerous rights),
non-human Tier-0 (backup/monitoring/vendor accounts in privileged groups),
secrets-in-attributes (beyond GPP), trust-bridges via GPO/certs, and the
hybrid seam (on-prem artifacts of Entra Connect / Seamless SSO `AZUREADSSOACC$`
never-rotated key / ADFS). On-prem AD reads only — never a call to the cloud.
