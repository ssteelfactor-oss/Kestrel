# Kestrel

Passive Active Directory security enumeration via native ADSI/COM interfaces.
No .NET. No PowerShell. No managed runtime. The query traffic is shaped like
routine domain activity — not because Kestrel hides, but because it speaks the
same interface the OS itself uses to talk to the directory.

> Kestrel lowers and normalizes its footprint. It does **not** claim invisibility:
> a domain controller with directory-query auditing enabled records Kestrel's
> reads like it records any LDAP client. See [Scope and non-goals](#scope-and-non-goals).

---

## The problem with existing tooling

If you work in AD security, you know BloodHound. It maps attack paths through
delegation chains, ACL edges, and group memberships, and it does it well. The
problem is not what it does — it is how it does it.

SharpHound, BloodHound's collector, runs as a .NET assembly. It generates LDAP
traffic in patterns that no legitimate domain workstation produces, and it does
so from a managed runtime that EDR hooks and inspects. EDR flags it not because
it exploits anything, but because the behavioral signature is unmistakable. Same
story with ADRecon, PowerView, and most Python-based alternatives: the runtime
is the fingerprint.

This is a real problem for defenders running internal audits. You need to
enumerate your own domain to find misconfigurations before an attacker does, but
the common tooling announces itself loudly — both in its runtime and in the
*shape* of the traffic it puts on the wire.

## A different approach

Windows has had a native AD interface since Windows 2000: **ADSI** — Active
Directory Service Interfaces. It is a COM-based abstraction over LDAP that the OS
itself uses when domain-joined components query the directory. Group Policy
processing uses it. The MMC snap-ins use it. `net user /domain` uses it.

Built on ADSI, Kestrel's queries have the same *shape* as normal domain activity:
an authenticated LDAP bind followed by paged search requests — exactly what every
DC sees from every domain workstation, every minute of every day. There is no
managed runtime for EDR to hook, and nothing in the query pattern that stands out
from routine directory use.

What this approach does **not** do is make the activity unlogged. Directory reads
are still reads: a DC configured to audit them (expensive/inefficient search
logging, event 1644, or SACLs on directory access) will record Kestrel's queries
the same way it records any other client's. The goal is the absence of a
*distinct* signature, not the absence of a *record*. This is the foundation
Kestrel is built on, stated honestly.

## How it works

Kestrel is written in pure C using ADSI COM interfaces directly: no wrappers, no
abstractions. From the wire's perspective, nearly every operation is an
authenticated LDAP bind followed by paged search requests.

```c
IDirectorySearch *pSearch = NULL;
ADsGetObject(ldapPath, &IID_IDirectorySearch, (void **)&pSearch);
pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 2);
pSearch->lpVtbl->ExecuteSearch(pSearch, filter, attrs, count, &hSearch);
```

The one exception is **ADWS endpoint detection**, which performs a bare TCP
connect to port 9389 on each DC (connect + `SO_ERROR` check, no payload, no WCF
framing). It is the only behavior in Kestrel that is not a plain LDAP query — a
single, payload-free probe directed at the DC, never at a member host. It is
called out explicitly rather than folded into the "looks like normal LDAP" claim.

Groups are resolved by **Well-Known RID + Domain SID**, not by name. Kestrel works
correctly on domains installed in any language (English, Russian, German, etc.)
without hardcoded group-name strings.

## Scope and non-goals

Kestrel's philosophy is a hard boundary, not a preference. A capability belongs in
Kestrel only if **both** hold: (1) its traffic targets only the DC / directory
(or a SYSVOL read that is part of normal Group Policy processing), and (2) it
succeeds with the rights of an ordinary authenticated domain user.

By design, Kestrel therefore **does not**:

- send packets to member hosts (no host-touch enumeration of any kind);
- collect logged-on sessions, query SAMR/remote registry, or scan SMB shares;
- require local-administrator rights on any target;
- write to the directory — every operation is read-only;
- attempt to evade or disguise itself. It produces a *low and familiar* footprint,
  which is not the same as *no* footprint.

Anything that needs to touch a member host or needs privileges above a normal
domain user is out of scope by definition and belongs to a separate, explicitly
labeled active tool — not to Kestrel.

## Requirements

- Windows, domain-joined machine
- Authenticated domain user account (no elevated privileges required for most scans)
- Visual Studio 2019+ with Windows SDK
- Linked libraries: `activeds.lib`, `adsiid.lib`, `ws2_32.lib`, `advapi32.lib`

## Build

Open `Kestrel.sln` in Visual Studio, select **Release | x64**, build.

For a self-contained binary with no runtime DLL dependencies:
Project Properties → C/C++ → Code Generation → Runtime Library → **Multi-threaded (/MT)**

## Modules

### v0.1 — Five passive scans (`adws_scan.c`)

All queries are read-only. Zero packets sent to member hosts (the ADWS probe
targets DCs only, as noted above).

| Module                      | What it does                                                                                                                                                                                                                  |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ADWS Endpoint Detection** | Probes port 9389/TCP per DC. Raw TCP connect, SO\_ERROR verification, no WCF framing. The one non-LDAP behavior; payload-free; DC-directed only.                                                                             |
| **Computer Topology**       | Full computer inventory with SPN-based service inference. MSSQLSvc → SQL Server, WSMAN → WinRM, TERMSRV → RDP. One LDAP query covers the entire domain.                                                                      |
| **Delegation Risks**        | Separates three categories: unconstrained delegation (TGT forwarding), constrained delegation (msDS-AllowedToDelegateTo), and Protocol Transition / S4U2Self (UAC 0x1000000). Reported separately — different risk profiles. |
| **LAPS Coverage**           | Detects legacy LAPS (ms-Mcs-AdmPwdExpirationTime) and Windows LAPS 2023+ (msLAPS-EncryptedPasswordHistory). Splits computer population into managed/unmanaged with percentage breakdown.                                     |
| **Stale Computers**         | Uses lastLogonTimestamp as primary reference — it replicates across DCs, unlike lastLogon which is per-DC only. Both values reported side by side.                                                                           |

### v0.2 — ACL edge extraction (`KestrelACL.C`)

Enumerates all AD objects (user, group, computer, OU, domainDNS, container, GPO,
builtinDomain) and extracts DACL edges.

Extended Rights GUID→name mapping is built dynamically from
`CN=Extended-Rights,CN=Configuration` — no hardcoded GUID tables.

Classified edge types: `GenericAll`, `WriteDACL`, `WriteOwner`, `GenericWrite`,
`ExtendedRight`, `WriteProperty`, `CreateChild`, `DeleteChild`, `Self`.

Two read modes:

- **Plan A** — per-object `IDirectoryObject` bind (requires elevated rights in some environments)
- **Plan B** — reads `nTSecurityDescriptor` directly from the LDAP search column (works for any authenticated domain user)

Plan A is attempted first. On the first access denial, Kestrel switches to Plan B
automatically for all remaining objects, keeping the run within ordinary-user rights.

### v0.3 — Transitive group membership (`KestrelGroup.c`)

Expands high-value groups using `LDAP_MATCHING_RULE_IN_CHAIN` (OID
`1.2.840.113556.1.4.1941`). One LDAP query per group — the DC performs full
recursive traversal server-side, with no client-side BFS.

Groups are located by **RID**, not by name:

| RID     | Group                                 |
| ------- | ------------------------------------- |
| 512     | Domain Admins                         |
| 518     | Schema Admins                         |
| 519     | Enterprise Admins                     |
| 520     | Group Policy Creator Owners           |
| 521     | Read-only Domain Controllers          |
| 526     | Key Admins                            |
| 527     | Enterprise Key Admins                 |
| 548–551 | Account/Server/Print/Backup Operators |

After expansion, group membership is cross-referenced against the ACL edges from
v0.2 to surface attack paths: `member → [via group] → EdgeType → target`.

## Roadmap

| Version | Status | Description                                                                                              |
| ------- | ------ | -------------------------------------------------------------------------------------------------------- |
| v0.1    | ✅      | Five passive AD scans                                                                                    |
| v0.2    | ✅      | ACL edge extraction via IDirectoryObject / nTSecurityDescriptor                                          |
| v0.3    | ✅      | Transitive group membership via LDAP\_MATCHING\_RULE\_IN\_CHAIN                                          |
| v0.4    | 🔲     | In-memory graph from ACL + membership + delegation data. Structured export (JSON / YAML).                |
| v0.5    | 🔲     | BFS shortest-path finder: any principal → Domain Admins. Pure in-memory traversal over v0.4 data — no additional queries, no host contact. |

Every roadmap item stays inside the boundary in [Scope and non-goals](#scope-and-non-goals).
Edge types that would require touching member hosts — logged-on sessions, local-admin
relationships via remote SAM — are deliberately excluded from Kestrel's graph.

## Code quality

**SAL 2.0 annotations** on every function signature, validated by PREfast
(`/analyze`) at compile time. `_Must_inspect_result_` on HRESULT-returning
functions, `_Outptr_` vs `_Out_` where semantics differ.

**Single rootDSE resolution** — `defaultNamingContext` and
`configurationNamingContext` are read once at startup and passed as parameters.
No redundant DC round-trips.

**No runtime dependencies** when built with `/MT` — a single executable, no
VCRUNTIME DLLs required on the machine it runs from.

## Related

Parent project: [NetEnum](https://github.com/ssteelfactor-oss/NetEnum) — AD enumeration via ADSI/COM/LDAP.

## Author

[@ssteelfactor-oss](https://github.com/ssteelfactor-oss)
Security research and COM/Windows internals
