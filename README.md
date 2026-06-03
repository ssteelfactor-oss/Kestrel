# Kestrel

<<<<<<< HEAD
Passive Active Directory security enumeration via native ADSI/COM interfaces.
No .NET. No PowerShell. No managed runtime. The query traffic is shaped like
routine domain activity - not because Kestrel hides, but because it speaks the
same interface the OS itself uses to talk to the directory.

> Kestrel lowers and normalizes its footprint. It does **not** claim invisibility:
> a domain controller with directory-query auditing enabled records Kestrel's
> reads like it records any LDAP client. See [Scope and non-goals](#scope-and-non-goals).
=======
Passive Active Directory security enumeration via native ADSI/COM interfaces.  
No .NET. No PowerShell. No managed runtime. No detectable behavioral signature.
>>>>>>> caa28ef ( Changes to be committed:)

---

## The problem with existing tooling

<<<<<<< HEAD
If you work in AD security, you know BloodHound. It maps attack paths through
delegation chains, ACL edges, and group memberships, and it does it well. The
problem is not what it does - it is how it does it.
=======
If you work in AD security, you know BloodHound. It maps attack paths through delegation chains, ACL edges, and group memberships, and it does it well. The problem is not what it does. The problem is how it does it.
>>>>>>> caa28ef ( Changes to be committed:)

SharpHound, BloodHound's collector, runs as a .NET assembly. It generates LDAP traffic in patterns that no legitimate domain workstation produces. EDR solutions detect it & not because it exploits anything, but because the behavioral signature is unmistakable. Same story with ADRecon, PowerView, and most Python-based alternatives: the runtime is the fingerprint.

<<<<<<< HEAD
This is a real problem for defenders running internal audits. You need to
enumerate your own domain to find misconfigurations before an attacker does, but
the common tooling announces itself loudly - both in its runtime and in the
*shape* of the traffic it puts on the wire.

## A different approach

Windows has had a native AD interface since Windows 2000: **ADSI** - Active
Directory Service Interfaces. It is a COM-based abstraction over LDAP that the OS
itself uses when domain-joined components query the directory. Group Policy
processing uses it. The MMC snap-ins use it. `net user /domain` uses it.

Built on ADSI, Kestrel's queries have the same *shape* as normal domain activity:
an authenticated LDAP bind followed by paged search requests - exactly what every
DC sees from every domain workstation, every minute of every day. There is no
managed runtime for EDR to hook, and nothing in the query pattern that stands out
from routine directory use.
=======
This is an unsolved problem for defenders running internal audits. You need to enumerate your own domain to find misconfigurations before an attacker does, but every available tool announces itself loudly.

## A different approach

Windows has had a native AD interface since Windows 2000: **ADSI** - Active Directory Service Interfaces. It is a COM-based abstraction over LDAP that the OS itself uses when domain-joined components query the directory. Group Policy processing uses it. The MMC snap-ins use it. `net user /domain` uses it.

The traffic it produces is indistinguishable from normal domain activity because it *is* normal domain activity.
>>>>>>> caa28ef ( Changes to be committed:)

This is the foundation Kestrel is built on.

## How it works

Kestrel is written in pure C using ADSI COM interfaces directly: no wrappers, no abstractions. From the wire's perspective, every query is an authenticated LDAP bind followed by paged search requests. Exactly what every DC sees from every domain workstation, every minute of every day.

```
IDirectorySearch *pSearch = NULL;
ADsGetObject(ldapPath, &IID_IDirectorySearch, (void **)&pSearch);
pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 2);
pSearch->lpVtbl->ExecuteSearch(pSearch, filter, attrs, count, &hSearch);
```

<<<<<<< HEAD
The one exception is **ADWS endpoint detection**, which performs a bare TCP
connect to port 9389 on each DC (connect + `SO_ERROR` check, no payload, no WCF
framing). It is the only behavior in Kestrel that is not a plain LDAP query - a
single, payload-free probe directed at the DC, never at a member host. It is
called out explicitly rather than folded into the "looks like normal LDAP" claim.
=======
Groups are resolved by **Well-Known RID + Domain SID**, not by name. This means Kestrel works correctly on domains installed in any language (English, Russian, German, etc.) without hardcoded group name strings.
>>>>>>> caa28ef ( Changes to be committed:)

## A note on footprint

Everything described above is LDAP over ADSI - the directory enumeration is indistinguishable from normal domain traffic because it goes through the same interface the OS itself uses.

<<<<<<< HEAD
Kestrel's philosophy is a hard boundary, not a preference. A capability belongs in
Kestrel only if **both** hold: (1) its traffic targets only the DC / directory
(or a SYSVOL read that is part of normal Group Policy processing), and (2) it
succeeds with the rights of an ordinary authenticated domain user.

By design, Kestrel therefore **does not**:

- send packets to member hosts (no host-touch enumeration of any kind);
- collect logged-on sessions, query SAMR/remote registry, or scan SMB shares;
- require local-administrator rights on any target;
- write to the directory - every operation is read-only;
- attempt to evade or disguise itself. It produces a *low and familiar* footprint,
  which is not the same as *no* footprint.

Anything that needs to touch a member host or needs privileges above a normal
domain user is out of scope by definition and belongs to a separate, explicitly
labeled active tool - not to Kestrel.
=======
One module is the exception, and it is worth naming honestly: the GPO/policy audit (`--policy`) reads `Registry.pol` from the domain's **SYSVOL share over SMB**, not over LDAP. It is still read-only, still runs as an ordinary domain user, and still touches only the domain controller - this is exactly how every GPO auditing tool works, since the settings live in files, not in the directory. But it is SMB file access, so it does not share the pure-LDAP profile of the rest of the tool. If your threat model requires LDAP-only traffic, omit `--policy`.
>>>>>>> caa28ef ( Changes to be committed:)

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

<<<<<<< HEAD
### v0.1 - Five passive scans (`adws_scan.c`)
=======
### v0.1 Five passive scans (`adws_scan.c`)
>>>>>>> caa28ef ( Changes to be committed:)

All queries are read-only. Zero packets sent to target hosts.

| Module                      | What it does                                                                                                                                                                                                                 |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ADWS Endpoint Detection** | Probes port 9389/TCP per DC. Raw TCP connect, SO_ERROR verification, no WCF framing.                                                                                                                                        |
| **Computer Topology**       | Full computer inventory with SPN-based service inference. MSSQLSvc → SQL Server, WSMAN → WinRM, TERMSRV → RDP. One LDAP query covers the entire domain.                                                                      |
| **Delegation Risks**        | Separates three categories: unconstrained delegation (TGT forwarding), constrained delegation (msDS-AllowedToDelegateTo), and Protocol Transition / S4U2Self (UAC 0x1000000). Reported separately - different risk profiles. |
| **LAPS Coverage**           | Detects legacy LAPS (ms-Mcs-AdmPwdExpirationTime) and Windows LAPS 2023+ (msLAPS-EncryptedPasswordHistory). Splits computer population into managed/unmanaged with percentage breakdown.                                     |
<<<<<<< HEAD
| **Stale Computers**         | Uses lastLogonTimestamp as primary reference - it replicates across DCs, unlike lastLogon which is per-DC only. Both values reported side by side.                                                                           |

### v0.2 - ACL edge extraction (`KestrelACL.C`)
=======
| **Stale Computers**         | Uses lastLogonTimestamp as primary reference, it replicates across DCs, unlike lastLogon which is per-DC only. Both values reported side by side.                                                                            |

### v0.2 ACL edge extraction (`KestrelACL.C`)
>>>>>>> caa28ef ( Changes to be committed:)

Enumerates all AD objects (user, group, computer, OU, domainDNS, container, GPO, builtinDomain) and extracts DACL edges.

<<<<<<< HEAD
Extended Rights GUID→name mapping is built dynamically from
`CN=Extended-Rights,CN=Configuration` - no hardcoded GUID tables.
=======
Extended Rights GUID→name mapping is built dynamically from `CN=Extended-Rights,CN=Configuration` - no hardcoded GUID tables.
>>>>>>> caa28ef ( Changes to be committed:)

Classified edge types: `GenericAll`, `WriteDACL`, `WriteOwner`, `GenericWrite`, `ExtendedRight`, `WriteProperty`, `CreateChild`, `DeleteChild`, `Self`.

Two read modes:

- **Plan A** - per-object `IDirectoryObject` bind (requires elevated rights in some environments)
<<<<<<< HEAD
- **Plan B** - reads `nTSecurityDescriptor` directly from the LDAP search column (works for any authenticated domain user)
=======
- **Plan B** - reads `nTSecurityDescriptor` directly from LDAP search column (works for any authenticated domain user, same approach as BloodHound)
>>>>>>> caa28ef ( Changes to be committed:)

Plan A is attempted first. On first access denial, Kestrel switches to Plan B automatically for all remaining objects.

<<<<<<< HEAD
### v0.3 - Transitive group membership (`KestrelGroup.c`)

Expands high-value groups using `LDAP_MATCHING_RULE_IN_CHAIN` (OID
`1.2.840.113556.1.4.1941`). One LDAP query per group - the DC performs full
recursive traversal server-side, with no client-side BFS.
=======
### v0.3 Transitive group membership (`KestrelGroup.c`)

Expands high-value groups using `LDAP_MATCHING_RULE_IN_CHAIN` (OID `1.2.840.113556.1.4.1941`).

One LDAP query per group. The DC performs full recursive traversal server-side, no client-side BFS.
>>>>>>> caa28ef ( Changes to be committed:)

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

After expansion, cross-references group membership against ACL edges from v0.2 to surface attack paths: `member → [via group] → EdgeType → target`.

### v0.4 In-memory graph + report (`KestrelReport.c`)

Folds every collected relationship into a single in-memory directed graph - the one source of truth that every output format renders from. There is no LDAP at this stage: the graph is built entirely from data already collected in v0.2/v0.3 and the delegation/LAPS passes.

Nodes are deduplicated through a hash table keyed by **SID** (principals) or **DN** (objects). Every edge is typed and carries a uniform direction: **controller → controlled**.

Relationships folded into the graph:

- ACL edges from v0.2 - `GenericAll`, `WriteDACL`, `WriteOwner`, `GenericWrite`, `ExtendedRight`, `WriteProperty`
- Transitive `MemberOf` edges from v0.3
- Kerberos delegation - `Constrained` and `S4U2Self` (principal → target SPN host), and `RBCD` (allowed principal → computer, parsed from the security descriptor in `msDS-AllowedToActOnBehalfOfOtherIdentity`). Unconstrained delegation has no second endpoint and is recorded as a node property, not an edge.
- `CanReadLAPS` - principals permitted to read a computer's LAPS password attribute (reader → computer), resolved from the attribute's `schemaIDGUID` and the per-computer DACL. The secret itself is never read - only *who is allowed to* read it.

One graph, three outputs - format is chosen by the output file extension:

| Format   | Use                                                                                                                                                |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **HTML** | Self-contained interactive report. Force-directed graph (D3.js from CDN), per-edge-type filters, severity colouring, node detail panel, tier-0 highlighting. Nothing required on the target beyond a browser. |
| **JSON** | Strict, machine-readable export of the full node/edge set - for downstream tooling, diffing, or CI gates.                                          |
| **YAML** | The same model in YAML, for human-readable review.                                                                                                 |

All output is emitted as UTF-8, so non-ASCII object names (Cyrillic, etc.) survive intact in every format.

```
Kestrel.exe --acl --groups --report C:\out\graph.html
Kestrel.exe --acl --groups --report C:\out\graph.json
```

## Roadmap

<<<<<<< HEAD
| Version | Status | Description                                                                                              |
| ------- | ------ | -------------------------------------------------------------------------------------------------------- |
| v0.1    | ✅      | Five passive AD scans                                                                                    |
| v0.2    | ✅      | ACL edge extraction via IDirectoryObject / nTSecurityDescriptor                                          |
| v0.3    | ✅      | Transitive group membership via LDAP\_MATCHING\_RULE\_IN\_CHAIN                                          |
| v0.4    | ✅      | In-memory graph from ACL + membership + delegation data. Structured export (JSON / YAML).                |
| v0.5    | 🔲      | BFS shortest-path finder: any principal → Domain Admins. Pure in-memory traversal over v0.4 data - no additional queries, no host contact. |

Every roadmap item stays inside the boundary in [Scope and non-goals](#scope-and-non-goals).
Edge types that would require touching member hosts - logged-on sessions, local-admin
relationships via remote SAM - are deliberately excluded from Kestrel's graph.
=======
| Version | Status | Description                                                                           |
| ------- | ------ | ------------------------------------------------------------------------------------- |
| v0.1    | ✅      | Five passive AD scans                                                                 |
| v0.2    | ✅      | ACL edge extraction via IDirectoryObject                                              |
| v0.3    | ✅      | Transitive group membership via LDAP_MATCHING_RULE_IN_CHAIN                           |
| v0.4    | ✅      | In-memory graph from ACL + membership + delegation + LAPS. Interactive HTML report + JSON/YAML export. |
| v0.5    | 🔲      | BFS path finder. Attack path analysis: any principal → Domain Admins, shortest route. |

## Screens

ADWS scanning in progress... [![Kestrel output](https://github.com/ssteelfactor-oss/Kestrel/raw/main/assets/ADWSScan.png)](/ssteelfactor-oss/Kestrel/blob/main/assets/ADWSScan.png) Stall - active points detecting... [![Kestrel output](https://github.com/ssteelfactor-oss/Kestrel/raw/main/assets/stall-active.png)](/ssteelfactor-oss/Kestrel/blob/main/assets/stall-active.png) Searching domain SIDs... [![Kestrel output](https://github.com/ssteelfactor-oss/Kestrel/raw/main/assets/DomainSID.png)](/ssteelfactor-oss/Kestrel/blob/main/assets/DomainSID.png)
>>>>>>> caa28ef ( Changes to be committed:)

## Code quality

**SAL 2.0 annotations** on every function signature validated by PREfast (`/analyze`) at compile time. `_Must_inspect_result_` on HRESULT-returning functions, `_Outptr_` vs `_Out_` where semantics differ.

<<<<<<< HEAD
**Single rootDSE resolution** - `defaultNamingContext` and
`configurationNamingContext` are read once at startup and passed as parameters.
No redundant DC round-trips.

**No runtime dependencies** when built with `/MT` - a single executable, no
VCRUNTIME DLLs required on the machine it runs from.
=======
**Single rootDSE resolution** - `defaultNamingContext` and `configurationNamingContext` are read once at startup and passed as parameters. No redundant DC round-trips.

**No runtime dependencies** when built with `/MT` single executable, no VCRUNTIME DLLs required on target machine.
>>>>>>> caa28ef ( Changes to be committed:)

## Related

Parent project: [NetEnum](https://github.com/ssteelfactor-oss/NetEnum) - AD enumeration via ADSI/COM/LDAP.

## Author

[@ssteelfactor-oss](https://github.com/ssteelfactor-oss)  
Security research and COM/Windows internals
