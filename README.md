# Kestrel

Passive Active Directory security enumeration via native ADSI/COM interfaces.
No .NET. No PowerShell. No managed runtime.

---

## The problem with existing tooling

If you work in AD security, you know BloodHound. It maps attack paths through delegation chains, ACL edges, and group memberships, and it does it well. The problem is not what it does. The problem is how it does it.

SharpHound, BloodHound's collector, runs as a .NET assembly. It generates LDAP traffic in patterns that no legitimate domain workstation produces. EDR solutions detect it - not because it exploits anything, but because the behavioral signature is unmistakable. Same story with ADRecon, PowerView, and most Python-based alternatives: the runtime is the fingerprint.

This is an unsolved problem for defenders running internal audits. You need to enumerate your own domain to find misconfigurations before an attacker does, but every available tool announces itself loudly.

## A different approach

Windows has had a native AD interface since Windows 2000: **ADSI** - Active Directory Service Interfaces. It is a COM-based abstraction over LDAP that the OS itself uses when domain-joined components query the directory. Group Policy processing uses it. The MMC snap-ins use it. `net user /domain` uses it.

The traffic it produces is indistinguishable from normal domain activity because it *is* normal domain activity.

This is the foundation Kestrel is built on.

## How it works

Kestrel is written in pure C using ADSI COM interfaces directly: no wrappers, no abstractions. From the wire's perspective, every query is an authenticated LDAP bind followed by paged search requests. Exactly what every DC sees from every domain workstation, every minute of every day.

```c
IDirectorySearch *pSearch = NULL;
ADsGetObject(ldapPath, &IID_IDirectorySearch, (void **)&pSearch);
pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 2);
pSearch->lpVtbl->ExecuteSearch(pSearch, filter, attrs, count, &hSearch);
```

Groups are resolved by **Well-Known RID + Domain SID**, not by name. This means Kestrel works correctly on domains installed in any language (English, Russian, German, etc.) without hardcoded group name strings.

## Footprint, honestly

Kestrel is **low-observable, not invisible**, and the README will never claim otherwise.

Most modules issue authenticated LDAP binds and paged searches through ADSI - the same COM path the OS uses for Group Policy, MMC, and `net user /domain`. On the wire that traffic is normal domain activity because it *is* normal domain activity, and it requires only an ordinary domain user.

Two honest caveats:

- **GPO policy audit (`KestrelPolicy.c`)** is the one module that steps outside LDAP. GPO settings live as files on SYSVOL, so it reads `Registry.pol` from `\\domain\SYSVOL` over SMB. Normal for any domain member - but it is a file-share read, not an LDAP query.
- **Volume and timing still matter.** A full `--all` run against a large domain is more LDAP than a single workstation produces in a minute. If blending in matters, pace it and scope it.

Kestrel does not fragment queries, randomize timing, or hide. It looks normal because it does normal things - that is the design, and its honest limit.

## Requirements

- Windows, domain-joined machine
- Authenticated domain user account (no elevated privileges required for any scan)
- Visual Studio 2019+ with Windows SDK
- Linked libraries: `activeds.lib`, `adsiid.lib`, `ws2_32.lib`, `advapi32.lib`, `bcrypt.lib`

## Build

Open `Kestrel.sln` in Visual Studio, select **Release | x64**, build.

For a self-contained binary with no runtime DLL dependencies:
Project Properties → C/C++ → Code Generation → Runtime Library → **Multi-threaded (/MT)**

## Usage

```
Kestrel.exe                            # run all modules (default)
Kestrel.exe --acl --groups             # selective modules
Kestrel.exe --report C:\out\graph.html # build report (.html / .json / .yaml by extension)
Kestrel.exe --trust --gmsa --adcs      # v0.7 audits
Kestrel.exe --from "CONTOSO\svc_sql"   # attack paths FROM a principal
Kestrel.exe --verbose                  # trace output
Kestrel.exe --help
```

| Flag           | Module                                                        |
| -------------- | ------------------------------------------------------------ |
| `--adws`       | ADWS endpoint detection                                      |
| `--topology`   | Computer topology via SPN                                    |
| `--delegation` | Delegation risks                                             |
| `--laps`       | LAPS coverage                                                |
| `--stale`      | Stale computers                                              |
| `--acl`        | ACL edge extraction                                          |
| `--groups`     | Transitive group membership                                  |
| `--policy`     | GPO security policy audit (SYSVOL/SMB)                       |
| `--paths`      | Attack-path analysis over the graph                          |
| `--from <p>`   | Paths FROM a principal (SID/name); implies `--paths`         |
| `--roast`      | Kerberoastable + AS-REP Roastable                            |
| `--trust`      | Domain/forest trust posture                                  |
| `--gmsa`       | gMSA password reader enumeration                             |
| `--adcs`       | ADCS certificate-template / CA audit (ESC1-5/9)              |
| `--gpp`        | GPP cpassword recovery from SYSVOL (MS14-025)                |
| `--report <f>` | Write report (extension selects HTML / JSON / YAML)          |
| `--acl-raw`    | Disable default-ACL baseline (show raw ACL edges)           |

With no module flags, Kestrel runs everything.

## Modules

### v0.1 Five passive scans (`adws_scan.c`)

All queries are read-only. Zero packets sent to target hosts.

| Module                      | What it does                                                                                                                                                                                                                 |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ADWS Endpoint Detection** | Probes port 9389/TCP per DC. Raw TCP connect, SO\_ERROR verification, no WCF framing.                                                                                                                                        |
| **Computer Topology**       | Full computer inventory with SPN-based service inference. MSSQLSvc → SQL Server, WSMAN → WinRM, TERMSRV → RDP. One LDAP query covers the entire domain.                                                                      |
| **Delegation Risks**        | Separates three categories: unconstrained delegation (TGT forwarding), constrained delegation (msDS-AllowedToDelegateTo), and Protocol Transition / S4U2Self (UAC 0x1000000). Reported separately - different risk profiles. |
| **LAPS Coverage**           | Detects legacy LAPS (ms-Mcs-AdmPwdExpirationTime) and Windows LAPS 2023+ (msLAPS-EncryptedPasswordHistory). Splits computer population into managed/unmanaged with percentage breakdown.                                     |
| **Stale Computers**         | Uses lastLogonTimestamp as primary reference - it replicates across DCs, unlike lastLogon which is per-DC only. Both values reported side by side.                                                                           |

### v0.2 ACL edge extraction (`KestrelACL.c`)

Enumerates all AD objects (user, group, computer, OU, domainDNS, container, GPO, builtinDomain) and extracts DACL edges.

Extended Rights GUID→name mapping is built dynamically from `CN=Extended-Rights,CN=Configuration` - no hardcoded GUID tables.

Classified edge types: `GenericAll`, `WriteDACL`, `WriteOwner`, `GenericWrite`, `ExtendedRight`, `WriteProperty`, `CreateChild`, `DeleteChild`, `Self`.

Two read modes:

- **Plan A** - per-object `IDirectoryObject` bind (requires elevated rights in some environments)
- **Plan B** - reads `nTSecurityDescriptor` directly from the LDAP search column (works for any authenticated domain user, same approach as BloodHound)

Plan A is attempted first. On first access denial, Kestrel switches to Plan B automatically for all remaining objects.

A DCSync rights pass surfaces principals holding `GetChanges` + `GetChangesAll` over the domain head.

Since v0.8 a **default-ACL baseline** (`KestrelBaseline.c`) cuts the noise: every object's ACEs are compared against the `defaultSecurityDescriptor` for its class — and against AdminSDHolder for `adminCount=1` objects — so only the rights an admin actually delegated are reported, not the defaults every object is born with. `--acl-raw` disables the filter.

### v0.3 Transitive group membership (`KestrelGroup.c`)

Expands high-value groups using `LDAP_MATCHING_RULE_IN_CHAIN` (OID `1.2.840.113556.1.4.1941`).

One LDAP query per group. The DC performs full recursive traversal server-side - no client-side BFS.

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

Builds a single in-memory directed graph from ACL edges, group membership, and delegation. Nodes are keyed by SID in an open-addressing hash table; tier-0 principals (Domain/Enterprise Admins, DCs, krbtgt) are tagged.

Folded into the same graph:

- **gMSA read edges** - `CanReadGMSAPassword` (reader → gMSA), from v0.7.
- **Roastable node flags** - Kerberoastable / AS-REP Roastable marked as node properties.

Exports to a self-contained interactive **HTML** report (D3.js force graph with filtering and a node detail panel), **JSON**, and **YAML** - format chosen by output extension. All serialization is written with `fputs`, never `printf`-family, to sidestep MSVC `C4477` format-string pitfalls in CSS/JSON output.

### v0.5 Attack-path finder (`KestrelPath.c`)

Breadth-first search over the graph - shortest path by number of hops.

- **Reverse (default):** who can reach tier-0 targets.
- **Forward (`--from <principal>`):** what a given principal can compromise.

Uses a compact CSR adjacency representation and output caps (per-target and global) to stay tractable on large domains.

### v0.5 GPO security policy audit (`KestrelPolicy.c`)

The one module that steps outside LDAP (see *Footprint*). GPO settings live on SYSVOL, so this reads `Registry.pol` over SMB and parses `dSHeuristics`. Flags LLMNR, NBT-NS, WDigest, NTLMv1, and missing LDAP signing.

It also flags the **Onelogon** (WOOT'26) surface — the *Allow vulnerable Netlogon secure channel connections* allow-list, i.e. accounts permitted to use unsigned/unsealed Netlogon channels (the compatibility hole left by the 2020 Zerologon patch). Each GPO's `GptTmpl.inf` is read and its `VulnerableChannelAllowList` SDDL decoded into the exempted principals. Domain-GPO scope only — an allow-list written directly to a DC's local registry would need remote-registry RPC, which Kestrel does not do.

### v0.6 Roastable accounts (`KestrelRoast.c`)

- **Kerberoastable** - user accounts carrying an SPN (krbtgt excluded).
- **AS-REP Roastable** - accounts with `DONT_REQ_PREAUTH` (UAC `0x400000`).

Detection only - no ticket is ever requested. Findings are also folded into the graph as node properties.

### v0.7 Domain trust posture (`KestrelTrust.c`)

Enumerates `trustedDomain` objects and decodes direction, type, and `trustAttributes`. Flags missing SID filtering on **inbound external** trusts (the classic sIDHistory-injection surface), TGT delegation across a trust, and RC4. Within-forest and forest-transitive trusts are excluded from the SID-filter check - they filter by default, so flagging them would be a false positive.

### v0.7 gMSA password readers (`KestrelGMSA.c`)

Parses each gMSA's `msDS-GroupMSAMembership` DACL and lists the non-SYSTEM principals able to retrieve the managed password. Reader → gMSA edges feed the graph (`CanReadGMSAPassword`).

### v0.7 ADCS posture (`KestrelADCS.c`)

Passive certificate-template and CA audit from the Configuration NC, read-only, ordinary user:

| Class | Condition                                                                 |
| ----- | ------------------------------------------------------------------------- |
| ESC1  | enrollee-supplies-subject + auth EKU + low-priv enroll, no approval/co-sign |
| ESC2  | Any-Purpose (or no) EKU + low-priv enroll                                 |
| ESC3  | Certificate-Request-Agent EKU + low-priv enroll                           |
| ESC4  | template object writable by a broad principal (right + SID reported)      |
| ESC5  | CA / enrollment-service object writable by a broad principal              |
| ESC9  | `NO_SECURITY_EXTENSION` on an authentication template                     |

Findings are cross-referenced against templates actually published by a CA - an unpublished template is reported but flagged `published: no`. Property-scoped WriteProperty and default-locked templates are excluded from ESC4 to avoid false positives.

ESC6 (CA registry flag), ESC7 (CA role ACL), and ESC8 (web-enrollment endpoint) are intentionally **out of scope**: none is observable from a passive LDAP read.

### v0.7 GPP cpassword recovery (`KestrelGPP.c`)

Walks SYSVOL over SMB and parses every Group Policy Preferences XML (Groups, Services, ScheduledTasks, DataSources, Drives, Printers) for `cpassword` — credentials AES-encrypted with the key Microsoft published in 2014 (MS14-025). Any domain user can recover them, so they are decrypted and shown (with the account and GPO) to prove recoverability and force rotation. Largely legacy, but old values persist on SYSVOL for years. Same footprint as the policy audit (an SMB read of SYSVOL). Plaintext buffers are scrubbed with `SecureZeroMemory`.

### v0.8 Default-ACL baseline (`KestrelBaseline.c`)

Not a scan but a filter for the ACL module. It builds a baseline of "expected" ACEs from two authoritative, ordinary-user, pure-LDAP sources — each `classSchema`'s `defaultSecurityDescriptor`, and the `AdminSDHolder` DACL (for `adminCount=1` objects) — then suppresses object ACEs that match it. What remains is the set of genuine, admin-introduced delegations, not the rights every object inherits at birth. `--acl-raw` turns it off to show the raw set.

## Roadmap

| Version | Status | Description                                                                 |
| ------- | ------ | --------------------------------------------------------------------------- |
| v0.1    | ✅      | Five passive AD scans                                                       |
| v0.2    | ✅      | ACL edge extraction + DCSync rights                                         |
| v0.3    | ✅      | Transitive group membership via LDAP\_MATCHING\_RULE\_IN\_CHAIN             |
| v0.4    | ✅      | In-memory graph from ACL + membership + delegation. HTML / JSON / YAML.     |
| v0.5    | ✅      | BFS path finder + GPO security policy audit                                 |
| v0.6    | ✅      | Kerberoastable + AS-REP Roastable detection                                 |
| v0.7    | ✅      | Trust posture · gMSA password readers · ADCS ESC1-5/9 · GPP cpassword       |
| v0.8    | ✅      | Default-ACL baseline (delegation noise suppression) · Onelogon detection    |
| -       | 🔲      | LAPS coverage/health anomalies (expiry-based, incl. rotation suppression)   |
| -       | 🔲      | `ms-DS-MachineAccountQuota` + RBCD weaponizability enrichment               |
| -       | 🔲      | Trust / ADCS edges in the graph + report                                    |
| -       | 🔲      | ADExplorer snapshot as an offline input source (diff over time)             |

## Screens

ADWS scanning in progress…
[![Kestrel output](https://github.com/ssteelfactor-oss/Kestrel/raw/main/assets/ADWSScan.png)](/ssteelfactor-oss/Kestrel/blob/main/assets/ADWSScan.png)

Stale / active points detecting…
[![Kestrel output](https://github.com/ssteelfactor-oss/Kestrel/raw/main/assets/stall-active.png)](/ssteelfactor-oss/Kestrel/blob/main/assets/stall-active.png)

Searching domain SIDs…
[![Kestrel output](https://github.com/ssteelfactor-oss/Kestrel/raw/main/assets/DomainSID.png)](/ssteelfactor-oss/Kestrel/blob/main/assets/DomainSID.png)

## Code quality

**SAL 2.0 annotations** on every function signature, validated by PREfast (`/analyze`) at compile time. `_Must_inspect_result_` on HRESULT-returning functions, `_Outptr_` vs `_Out_` where semantics differ.

**Single rootDSE resolution** - `defaultNamingContext` and `configurationNamingContext` are read once at startup and passed as parameters. No redundant DC round-trips.

**No runtime dependencies** when built with `/MT` - single executable, no VCRUNTIME DLLs required on the target machine.

## Related

Parent project: [NetEnum](https://github.com/ssteelfactor-oss/NetEnum) - AD enumeration via ADSI/COM/LDAP.

## Author

[@ssteelfactor-oss](https://github.com/ssteelfactor-oss)
Security research and COM/Windows internals
