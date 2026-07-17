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

With no flags, Kestrel runs **every module** and prints to the console; add `--report` for a shareable artifact. Everything below runs as an ordinary authenticated domain user - no elevation.

```
Kestrel.exe                              # full posture sweep, console output
Kestrel.exe --report C:\out\report.html  # full sweep + interactive HTML report
```

Selecting any module flag runs **only** the modules you name. Graph outputs (`--report`, `--opengraph`) need the graph-building modules (`--acl --groups --delegation --trust --adcs`) - or just run bare (all modules) and add the output flag.

### Commands by what you're looking for

**"Who can take over the domain?" - attack paths to Tier-0**

```
Kestrel.exe --acl --groups --delegation --report C:\out\paths.html
```

Full graph (ACL edges + transitive privileged membership + delegation); every path reaching Domain/Enterprise Admins, DCs, or krbtgt.

**"What can THIS account reach?" - blast radius of one principal**

```
Kestrel.exe --from "CONTOSO\svc_sql"
Kestrel.exe --from S-1-5-21-1111111111-2222222222-3333333333-1104
```

Forward BFS from a principal (SID or `DOMAIN\name`); implies `--paths`.

**"Who has dangerous rights over objects?" - ACL abuse**

```
Kestrel.exe --acl            # delegated GenericAll/WriteDacl/WriteOwner/DCSync (baseline-filtered)
Kestrel.exe --acl --acl-raw  # raw ACLs, no default-ACL suppression
```

Includes DCSync holders and RBCD-weaponizable / cross-forest (`[FOREIGN]`) writes on computers.

**"Any delegation abuse?" - unconstrained / constrained / RBCD**

```
Kestrel.exe --delegation
```

Unconstrained (TGT), constrained (`msDS-AllowedToDelegateTo`), S4U2Self, and RBCD - RBCD grants tagged weaponizable (MAQ > 0) and foreign-SID, with "when configured / from which DSA" provenance.

**"Kerberoast / AS-REP targets?"**

```
Kestrel.exe --roast
```

**"Any planted persistence?" - shadow credentials**

```
Kestrel.exe --shadowcreds
```

Objects carrying `msDS-KeyCredentialLink`, decoded to key usage + creation time, with "when set / from which DSA" provenance. User/service accounts, `adminCount=1` holders, and keys added in the last 90 days are flagged (computers carry device keys legitimately).

**"Any injected SID history?" - stealthy escalation / persistence**

```
Kestrel.exe --sidhistory
```

Objects with a populated `sIDHistory`, each historical SID classified: `[PRIVILEGED]` (a well-known admin SID injected for stealthy escalation, local or cross-forest) or `[FOREIGN]` (a SID from another domain/forest). Each carries "when injected / from which DSA" provenance, and feeds the graph as a `HasSIDHistory` edge.

**"Any orphaned admin markers?" - AdminSDHolder residue**

```
Kestrel.exe --adminsdholder
```

`adminCount=1` objects that are no longer a member of any protected group - orphaned SDProp markers with a frozen, non-inheriting security descriptor (residual privileged posture, a classic backdoor-marker hiding spot). Cross-references transitive membership of the real protected-group set; each orphan carries `nTSecurityDescriptor` provenance. (Dangerous ACEs planted on the AdminSDHolder object itself surface through `--acl`.)

**"Is the domain spray-friendly?" - entry-condition posture**

```
Kestrel.exe --pwdpolicy
```

The preconditions an attacker checks before the first credential: the default domain password policy (`lockoutThreshold=0` → `[SPRAY-SAFE]`, weak length / no complexity / non-expiring passwords), Fine-Grained PSOs (per-principal overrides often weaker than the default, with who they apply to), krbtgt password age (`[CRITICAL]` when the key hasn't rotated - Golden Ticket exposure), and `ms-DS-MachineAccountQuota > 0` (noPac / Certifried enabler).

**"Any weak-credential accounts?" - credential hygiene**

```
Kestrel.exe --hygiene
```

Accounts whose `userAccountControl` widens the credential surface: `PASSWD_NOTREQD` (empty password possible - flagged hard on enabled accounts), `DONT_EXPIRE_PASSWORD` (password never rotates), and `ENCRYPTED_TEXT_PWD_ALLOWED` (reversible encryption - plaintext recoverable from NTDS), plus secret-like text in `description` / `info`. Enabled and `adminCount=1` accounts are highlighted.

**"Who is local admin where?" - GPO-delivered lateral movement**

```
Kestrel.exe --gpolateral
```

Restricted Groups in each GPO's `GptTmpl.inf` push local-group membership onto every computer the GPO applies to. Kestrel maps the privileged local groups to BloodHound's lateral edges - Administrators → `AdminTo`, Remote Desktop Users → `CanRDP`, Remote Management Users → `CanPSRemote`, Distributed COM Users → `ExecuteDCOM` - resolves each GPO's links to the computers in scope, and emits principal → computer edges that become native pathfinding edges in the graph and OpenGraph export.

**"What ACL misconfigurations is nobody checking?" - delegation & ACL structure (ADeleg-class)**

```
Kestrel.exe --acl        # owner ≠ admin · disabled inheritance · non-canonical order · orphaned trustees · low-priv → Tier-0
Kestrel.exe --schema     # schema defaultSecurityDescriptor backdoor
```

Structural checks that catch what a right-by-right blacklist misses, in the spirit of ADeleg: an object **owned by a non-admin** (a hidden GenericAll), an object with **inheritance disabled** (fallen out of the domain's ACL model), a **non-canonical DACL** (ACEs hand-edited out of order), an **ACE for an orphaned trustee** (unresolvable SID left by a deleted account), and - the flagship - any **low-privilege trustee (Everyone / Authenticated Users / Domain Users) with an edge into a Tier-0 resource**. `--schema` separately parses every class's `defaultSecurityDescriptor` and flags one that grants a dangerous right to a low-priv principal - a backdoor that makes every future object of that class born controllable.

**"Certificate escalation?" - ADCS ESC1-5/9**

```
Kestrel.exe --adcs
```

**"gMSA password readers?"**

```
Kestrel.exe --gmsa
```

**"Cleartext creds in SYSVOL?" - GPP cpassword**

```
Kestrel.exe --gpp
```

**"Trust / cross-forest exposure?"**

```
Kestrel.exe --trust
```

SID-filtering gaps on inbound external trusts, TGT delegation across a trust, RC4.

**"Privileged group membership - and who was added recently?"**

```
Kestrel.exe --groups
```

Transitive membership of DA/EA/operators/DnsAdmins + members **added in the last 90 days** (with originating DSA).

**"GPO / policy weaknesses?"**

```
Kestrel.exe --policy
```

LLMNR/NBT-NS/WDigest/NTLMv1, LDAP + SMB signing, anonymous LDAP, Onelogon allow-list, and DA-equivalent User Rights (`SeBackup`/`SeDebug`/…).

**"Password-hygiene surface?" - LAPS + stale**

```
Kestrel.exe --laps    # coverage + rotation anomalies (expired / future-dated / dual-schema)
Kestrel.exe --stale   # dormant computers via lastLogonTimestamp
```

**"Recon surface exposed?" - ADWS + topology**

```
Kestrel.exe --adws       # ADWS endpoint per DC (9389/TCP)
Kestrel.exe --topology   # computer inventory + services via SPN
```

### Output & continuous audit

**Shareable / machine-readable report** - format chosen by extension:

```
Kestrel.exe --report C:\out\report.html   # interactive D3 force graph
Kestrel.exe --report C:\out\graph.json     # JSON
Kestrel.exe --report C:\out\graph.yaml     # YAML
```

**Feed into BloodHound CE** - OpenGraph export:

```
Kestrel.exe --opengraph C:\out\kestrel.json
```

Import via **BloodHound CE → Administration → File Ingest**. Every Kestrel edge (including RBCD-weaponizable, foreign-SID, `ADCS_ESC`, `Trusts`) becomes queryable in Cypher. Tagged `source_kind: Kestrel` for one-click cleanup.

**"What changed since last time?" - diff over time**

```
Kestrel.exe --report C:\snap\week1.json                            # baseline snapshot
Kestrel.exe --report C:\snap\week2.json --diff C:\snap\week1.json  # new run + diff
```

Surfaces **new / removed** attack-path edges (new GenericAll, new RBCD, new ESC, new privileged membership) since the snapshot; new edges into Tier-0 are flagged.

**Everything at once** - full sweep, HTML for humans, OpenGraph for BloodHound:

```
Kestrel.exe --report C:\out\report.html --opengraph C:\out\kestrel.json
```

### Flag reference

| Flag             | Purpose                                                              |
| ---------------- | ------------------------------------------------------------------- |
| `--adws`         | ADWS endpoint detection (9389/TCP per DC)                           |
| `--topology`     | Computer inventory + service inference via SPN                      |
| `--delegation`   | Delegation risks (unconstrained / constrained / S4U2Self / RBCD)    |
| `--laps`         | LAPS coverage + rotation-health anomalies                           |
| `--stale`        | Stale computers via `lastLogonTimestamp`                            |
| `--acl`          | ACL edge extraction (+ DCSync, RBCD-weaponizable, foreign-SID)      |
| `--groups`       | Transitive privileged membership + recent-add provenance           |
| `--policy`       | GPO security policy audit (signing, WDigest, User Rights, …)        |
| `--paths`        | Attack-path analysis over the graph (to Tier-0)                     |
| `--from <prin>`  | Paths FROM a principal (SID/name); implies `--paths`               |
| `--roast`        | Kerberoastable + AS-REP Roastable                                   |
| `--shadowcreds`  | Shadow credentials (`msDS-KeyCredentialLink`)                       |
| `--sidhistory`   | sIDHistory enumeration (privileged / foreign SID injection)        |
| `--adminsdholder`| Orphaned `adminCount=1` objects (AdminSDHolder residue)            |
| `--pwdpolicy`    | Password policy + PSO · krbtgt age · MachineAccountQuota (noPac)   |
| `--hygiene`      | Credential hygiene (`PASSWD_NOTREQD` / `DONT_EXPIRE` / reversible / description) |
| `--gpolateral`   | GPO local-group → lateral edges (`AdminTo`/`CanRDP`/`CanPSRemote`/`ExecuteDCOM`) |
| `--schema`       | Schema `defaultSecurityDescriptor` audit (schema-level backdoor)   |
| `--trust`        | Domain/forest trust posture                                        |
| `--gmsa`         | gMSA password-reader enumeration                                   |
| `--adcs`         | ADCS certificate-template / CA audit (ESC1-5/9)                     |
| `--gpp`          | GPP cpassword recovery from SYSVOL (MS14-025)                       |
| `--all`          | Run all modules explicitly                                          |
| `--report <f>`   | Report file (`.html` / `.json` / `.yaml` by extension)             |
| `--opengraph <f>`| BloodHound CE OpenGraph JSON export                                 |
| `--diff <f>`     | Diff current run against a previous `.json` snapshot                |
| `--acl-raw`      | Disable default-ACL baseline (show raw ACL edges)                   |
| `--verbose` / `-v` | Trace output                                                      |
| `--version`      | Show version and exit                                              |
| `--help` / `-h`  | Show help and exit                                                 |

With no module flags, Kestrel runs everything.

## Modules

### v0.1 Six passive scans (`adws_scan.c`)

All queries are read-only. Zero packets sent to target hosts.

| Module                      | What it does                                                                                                                                                                                                                 |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ADWS Endpoint Detection** | Probes port 9389/TCP per DC. Raw TCP connect, SO\_ERROR verification, no WCF framing.                                                                                                                                        |
| **Computer Topology**       | Full computer inventory with SPN-based service inference. MSSQLSvc → SQL Server, WSMAN → WinRM, TERMSRV → RDP. One LDAP query covers the entire domain.                                                                      |
| **Delegation Risks**        | Separates three categories: unconstrained delegation (TGT forwarding), constrained delegation (msDS-AllowedToDelegateTo), and Protocol Transition / S4U2Self (UAC 0x1000000). Reported separately - different risk profiles. |
| **LAPS Health**             | Reads only the expiration timestamps (world-readable - not the password) for legacy and Windows LAPS. Beyond managed/unmanaged coverage it flags anomalies: expired (rotation stalled), future-dated (rotation suppressed - a persistence signal), dual-schema, and never-managed. DCs excluded.                     |
| **Stale Computers**         | Uses lastLogonTimestamp as primary reference - it replicates across DCs, unlike lastLogon which is per-DC only. Both values reported side by side.                                                                           |
| **Sensitive Descriptions**  | Reads user `description` / `info` / `comment` (world-readable) and flags leaked secrets and role/weakness hints - passwords, "Domain Admin", "DCSync", "GMSA", "LAPS", "shadow credential". Admins routinely annotate accounts with their own weaknesses.                                                                  |

### v0.2 ACL edge extraction (`KestrelACL.c`)

Enumerates all AD objects (user, group, computer, OU, domainDNS, container, GPO, builtinDomain) and extracts DACL edges.

Extended Rights GUID→name mapping is built dynamically from `CN=Extended-Rights,CN=Configuration` - no hardcoded GUID tables.

Classified edge types: `GenericAll`, `WriteDACL`, `WriteOwner`, `GenericWrite`, `ExtendedRight`, `WriteProperty`, `CreateChild`, `DeleteChild`, `Self`.

Two read modes:

- **Plan A** - per-object `IDirectoryObject` bind (requires elevated rights in some environments)
- **Plan B** - reads `nTSecurityDescriptor` directly from the LDAP search column (works for any authenticated domain user, same approach as BloodHound)

Plan A is attempted first. On first access denial, Kestrel switches to Plan B automatically for all remaining objects.

A DCSync rights pass surfaces principals holding `GetChanges` + `GetChangesAll` over the domain head.

Since v0.8 a **default-ACL baseline** (`KestrelBaseline.c`) cuts the noise: every object's ACEs are compared against the `defaultSecurityDescriptor` for its class - and against AdminSDHolder for `adminCount=1` objects - so only the rights an admin actually delegated are reported, not the defaults every object is born with. `--acl-raw` disables the filter.

**MAQ + RBCD weaponizability.** The scan reads `ms-DS-MachineAccountQuota` (default 10) as a posture finding, then labels every write on a computer object (`GenericAll`/`GenericWrite`/`WriteDacl`/`WriteOwner`, or a write of the RBCD attribute) as *RBCD-weaponizable now* when MAQ > 0 - because the attacker can also mint the machine account with an SPN needed to finish S4U2Proxy. With MAQ = 0 the same path is flagged RBCD-capable but not immediately weaponizable.

**Cross-forest RBCD.** When an RBCD grant (`msDS-AllowedToActOnBehalfOfOtherIdentity`) names a principal from another domain or forest, its SID does not resolve locally. Kestrel compares each trustee's domain SID against the local domain and tags foreign principals `[FOREIGN - cross-domain/forest RBCD]` - the exact signal the defensive guidance says to resolve.

### v0.3 Transitive group membership (`KestrelGroup.c`)

Expands high-value groups using `LDAP_MATCHING_RULE_IN_CHAIN` (OID `1.2.840.113556.1.4.1941`).

One LDAP query per group. The DC performs full recursive traversal server-side - no client-side BFS.

High-value groups are located by **well-known SID**, not by name - locale-independent. Domain groups (`S-1-5-21-…-RID`): Domain Admins (512), Schema Admins (518), Enterprise Admins (519), Group Policy Creator Owners (520), Read-only Domain Controllers (521), Key Admins (526), Enterprise Key Admins (527). BUILTIN aliases (`S-1-5-32-RID`): Administrators (544), Account/Server/Print/Backup Operators (548–551), Hyper-V Administrators (578). Groups with no fixed RID are resolved by name: **DnsAdmins** (arbitrary DLL load into `dns.exe` as SYSTEM on a DC) and DHCP Administrators.

After expansion, cross-references group membership against ACL edges from v0.2 to surface attack paths: `member → [via group] → EdgeType → target`.

**Provenance** (`KestrelProvenance.c`). For each high-value group, Kestrel reads the constructed `msDS-ReplValueMetaData` attribute (per-member replication metadata) and surfaces members **added within the last 90 days** - with the add time and the **originating DSA**. Recently-added privileged members are a classic persistence signal that raw membership does not reveal. The attribute is readable by anyone who can read the object (*not* gated by DS-Replication-Get-Changes / DCSync), is requested per-object (targeted, small footprint), and degrades silently if unavailable. The same primitive also runs single-attribute (`msDS-ReplAttributeMetaData`) provenance on high-value findings - when an object's DACL (`nTSecurityDescriptor`), an RBCD grant, or a shadow-credential key was last written, and from which DSA.

### v0.4 In-memory graph + report (`KestrelReport.c`)

Builds a single in-memory directed graph from ACL edges, group membership, and delegation. Nodes are keyed by SID in an open-addressing hash table; tier-0 principals (Domain/Enterprise Admins, DCs, krbtgt) are tagged.

Folded into the same graph:

- **gMSA read edges** - `CanReadGMSAPassword` (reader → gMSA), from v0.7.
- **Roastable node flags** - Kerberoastable / AS-REP Roastable marked as node properties.
- **Trust edges** - `Trusts` (local domain → trusted domain), carrying direction and SID-filtering status.
- **ADCS escalation edges** - `ADCS_ESC` (enrollee/writer → domain), labelled with the ESC class and template, so certificate paths join the same graph as ACL and membership.
- **SID-history edges** - `HasSIDHistory` (holder → the SID it carries), so injected privileged/foreign SIDs become a first-class path in the graph.
- **Fine-grained ACL edges** - object-specific ACEs are classified to their canonical BloodHound kinds: `ForceChangePassword`, `WriteSPN` (targeted Kerberoast), `AddKeyCredentialLink` (shadow credentials), and `AddSelf`, instead of a generic ExtendedRight / WriteProperty.
- **GPO lateral edges** - `AdminTo` / `CanRDP` / `CanPSRemote` / `ExecuteDCOM` (principal → computer), derived from Restricted-Groups local-group membership and resolved to the computers each GPO applies to.

Exports to a self-contained interactive **HTML** report (D3.js force graph with filtering and a node detail panel), **JSON**, and **YAML** - format chosen by output extension. All serialization is written with `fputs`, never `printf`-family, to sidestep MSVC `C4477` format-string pitfalls in CSS/JSON output.

**BloodHound CE export** (`--opengraph`, `KestrelWriteOpenGraph`): the same in-memory graph is emitted as OpenGraph generic nodes/edges JSON, keyed by SID, with Kestrel's edge types mapped to canonical BloodHound kinds (`GenericAll`, `MemberOf`, `AllowedToAct`, `ReadGMSAPassword`, …) where they map and descriptive names otherwise. Tagged `source_kind: Kestrel`. Import via File Ingest for Cypher over Kestrel's graph - including edges SharpHound does not produce (RBCD-weaponizable, foreign-SID, `ADCS_ESC`).

**Diff over time** (`--diff`, `KestrelDiff.c`): compares the current graph against a previous Kestrel `.json` snapshot and reports new / removed attack-path edges, keyed by `(sourceSID · type · targetSID)` so run-to-run node re-indexing never creates false diffs. New edges into Tier-0 are flagged - a continuous-audit signal with no new directory reads.

### v0.5 Attack-path finder (`KestrelPath.c`)

Breadth-first search over the graph - shortest path by number of hops.

- **Reverse (default):** who can reach tier-0 targets.
- **Forward (`--from <principal>`):** what a given principal can compromise.

Uses a compact CSR adjacency representation and output caps (per-target and global) to stay tractable on large domains.

### v0.5 GPO security policy audit (`KestrelPolicy.c`)

The one module that steps outside LDAP (see *Footprint*). GPO settings live on SYSVOL, so this reads `Registry.pol` over SMB and parses `dSHeuristics`. Flags LLMNR, NBT-NS, WDigest, NTLMv1, and missing LDAP signing.

It also flags the **Onelogon** (WOOT'26) surface - the *Allow vulnerable Netlogon secure channel connections* allow-list, i.e. accounts permitted to use unsigned/unsealed Netlogon channels (the compatibility hole left by the 2020 Zerologon patch). Each GPO's `GptTmpl.inf` is read and its `VulnerableChannelAllowList` SDDL decoded into the exempted principals. Domain-GPO scope only - an allow-list written directly to a DC's local registry would need remote-registry RPC, which Kestrel does not do.

**SMB signing** is checked from each GPO's `GptTmpl.inf` (`RequireSecuritySignature`, server and client) - the control that blocks the NTLM relay/reflection class (CVE-2025-33073, CVE-2026-24294). Server-side drives the verdict; when it isn't defined the result is `UNKNOWN`, since the OS default applies and member servers / Server 2025 do not require it by default.

**Anonymous LDAP posture** is read straight from the directory: `dSHeuristics` (7th character, `fLDAPBlockAnonOps`) reveals whether anonymous LDAP bind/search is enabled, and the **Pre-Windows 2000 Compatible Access** group is inspected for Anonymous Logon / Everyone members - either one reopens the pre-credential enumeration surface.

**Dangerous User Rights Assignment.** The `[Privilege Rights]` section of each GPO's `GptTmpl.inf` is parsed for DA-equivalent privileges - `SeBackup`/`SeRestore` (read past every ACL, dump `ntds.dit`), `SeDebug` (LSASS), `SeTakeOwnership`/`SeLoadDriver`/`SeTcb`/`SeImpersonate`/`SeCreateToken` (SYSTEM) - granted to a *domain* principal (`S-1-5-21-…`) rather than only the built-in holders. Such a grant is domain-admin-equivalent and usually invisible to attack-graph tools, because it is a privilege, not an ACE.

### v0.6 Roastable accounts (`KestrelRoast.c`)

- **Kerberoastable** - user accounts carrying an SPN (krbtgt excluded).
- **AS-REP Roastable** - accounts with `DONT_REQ_PREAUTH` (UAC `0x400000`).

Detection only - no ticket is ever requested. Findings are also folded into the graph as node properties.

### Shadow credentials (`KestrelShadowCreds.c`)

Detects planted **shadow credentials** - the persistence half of the PKINIT / Whisker attack, invisible to ACL analysis because the artifact is an attribute value, not an ACE. Enumerates every object with a populated `msDS-KeyCredentialLink` and decodes each `KEYCREDENTIALLINK_BLOB` (MS-ADTS 2.2.20) to its key usage (`NGC` is the WHfB / attacker key type) and creation time. A key credential on a *computer* is usually a legitimate device key; one on a *user*, service, or `adminCount=1` account is the classic shadow-credential signal and is flagged, as are keys created in the last 90 days. Each object also carries `msDS-KeyCredentialLink` provenance (when the value was written, and from which DSA). Read-only, ordinary user - ADSI hands back the DN-Binary value already separated from the owner DN and hex-decoded.

### SID history (`KestrelSidHistory.c`)

Enumerates every object with a populated `sIDHistory` and classifies each historical SID. A **privileged** SID (a well-known admin RID - DA/EA/Schema/DCs/RODCs/Key Admins/krbtgt, or a BUILTIN admin alias - in any domain, so cross-forest injection is caught) is a stealthy-escalation signal: it grants that access on every logon with no group membership and no ACE. A **foreign** SID (from another domain/forest) is the migration/cross-forest case, the pair to the foreign-SID RBCD finding. Each holder carries `sIDHistory` provenance (when injected, from which DSA), and each historical SID becomes a `HasSIDHistory` edge in the graph.

### Orphaned adminCount (`KestrelAdminSDHolder.c`)

SDProp stamps `adminCount=1` and disables ACE inheritance on members of protected groups; when an object is later removed from the group, the marker and the frozen, non-inheriting security descriptor are **not** rolled back and no event is written. This scan builds the set of currently-protected principals - the SDProp-protected groups, their transitive members (`LDAP_MATCHING_RULE_IN_CHAIN`), and the protected users Administrator/krbtgt - and flags every `adminCount=1` object that is no longer in it. Such an orphan carries residual privileged ACL posture and a stealthy non-inheriting SD, and is a classic hiding spot for a planted backdoor marker; each gets `nTSecurityDescriptor` provenance. The other AdminSDHolder axis - dangerous ACEs planted on the `CN=AdminSDHolder` / `CN=System` objects themselves - is already surfaced by the ACL scan, which walks the whole domain NC subtree.

### Password policy & entry-condition posture (`KestrelPwdPolicy.c`)

The preconditions that precede the first credential. The **default domain password policy** is read from the NC head - `lockoutThreshold == 0` flags the domain `[SPRAY-SAFE]` (password spraying is unthrottled), with weak `minPwdLength`, disabled complexity, and non-expiring `maxPwdAge` as supporting notes. **Fine-Grained Password Policies** (`msDS-PasswordSettings` objects) are enumerated with their precedence, thresholds, and `msDS-PSOAppliesTo` targets - per-principal overrides are frequently weaker than the domain default and applied to service accounts. **krbtgt password age** (`pwdLastSet` on `krbtgt` and RODC `krbtgt_*`) is flagged `[CRITICAL]` when the key has not rotated - a leaked hash still forges valid Golden Tickets. And **`ms-DS-MachineAccountQuota > 0`** is surfaced as the noPac (CVE-2021-42278/42287) and Certifried (CVE-2022-26923) enabler. Read-only: one base read of the domain object, one krbtgt search, one PSO-container enumeration.

### Credential hygiene (`KestrelHygiene.c`)

A cheap `userAccountControl` / attribute sweep for the accounts an attacker sprays and cracks against. `PASSWD_NOTREQD` (0x20) means the account may carry an **empty password** - flagged hard when the account is enabled. `DONT_EXPIRE_PASSWORD` (0x10000) leaves a secret in place indefinitely, and `ENCRYPTED_TEXT_PWD_ALLOWED` (0x80) stores it with **reversible encryption**, recoverable to plaintext from NTDS. Finally, `description` / `info` are checked for secret-like text - a credential typed into an attribute every authenticated user can read. Enabled and `adminCount=1` accounts are highlighted; only accounts with at least one issue are printed.

### GPO lateral-movement edges (`KestrelGpoLateral.c`)

Restricted Groups in a GPO's `GptTmpl.inf` (`[Group Membership]`) set local-group membership on every computer the GPO applies to - the lateral-movement surface BloodHound models as edges. Kestrel maps the privileged local groups to their canonical kinds (Administrators → `AdminTo`, Remote Desktop Users → `CanRDP`, Remote Management Users → `CanPSRemote`, Distributed COM Users → `ExecuteDCOM`), resolves each GPO's `gPLink` to the OUs that link it, enumerates the computers in those subtrees, and emits a principal → computer edge for each. Read-only LDAP + SYSVOL. Scope note: it resolves "GPO linked to OU → applies to every computer in the subtree" and does **not** yet model block-inheritance, security filtering, WMI filtering, or enforced links, and reads SID-form members only - so edges are candidates in heavily-filtered environments.

### Delegation & ACL structure audit (`KestrelACL.C`, `KestrelSchemaAudit.c`)

A right-by-right blacklist (GenericAll, DCSync, …) misses *structural* ACL problems - the class of issue ADeleg surfaces. Alongside its edge extraction, the ACL scan flags: objects whose **owner is not an admin** (the owner can rewrite the DACL at will - a hidden GenericAll); objects with **DACL inheritance disabled** (`SE_DACL_PROTECTED`), which have quietly fallen out of the domain's inheritance model; **non-canonical DACLs**, where ACEs are out of the canonical deny-before-allow / explicit-before-inherited order (a hand-editing / tampering marker); and **orphaned trustees**, explicit ACEs for a domain SID that no longer resolves. Over the built + Tier-0-tagged graph it then reports every **low-privilege trustee → Tier-0 resource** edge (Everyone / Authenticated Users / Domain Users / Users granted control over a Tier-0 object) - ADeleg's highest-signal view, the `Everyone : FullControl` on the domain root class of finding.

Separately, `--schema` (`KestrelSchemaAudit.c`) reads every `classSchema` object's `defaultSecurityDescriptor` and, rather than diffing against a brittle per-version baseline, parses the SDDL and flags any ACE granting a dangerous right to a low-privilege principal. That default is stamped onto the DACL of every **new** object of the class, so a single edit is a silent, forward-looking, domain-wide backdoor with no ACE on any existing object to find; flagged classes carry `defaultSecurityDescriptor` provenance.

### v0.7 Domain trust posture (`KestrelTrust.c`)

Enumerates `trustedDomain` objects and decodes direction, type, and `trustAttributes`. Flags missing SID filtering on **inbound external** trusts (the classic sIDHistory-injection surface), TGT delegation across a trust, and RC4. Within-forest and forest-transitive trusts are excluded from the SID-filter check - they filter by default, so flagging them would be a false positive. Since v0.10 trusts also feed the graph as domain→domain `Trusts` edges.

For every **incoming** trust the trust account (`<flatName>$`) lives locally, and its keys can be extracted from the trusting side to request a TGT here - a one-way-trust weakness whose only real mitigation is an Authentication Policy assigned to that account. Kestrel reads the trust account's `msDS-AssignedAuthNPolicy` and flags `VULN: trust-acct no AuthN Policy (TGT abuse)` when it is unset, and reads `primaryGroupID` (legacy `513` vs the Server 2025 `528`/`529`) as context. Per Jorge's forest-boundary analysis, the 2025 group change alone does **not** block the attack - only the policy does - so the policy drives the verdict.

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

ESC6 (CA registry flag), ESC7 (CA role ACL), and ESC8 (web-enrollment endpoint) are intentionally **out of scope**: none is observable from a passive LDAP read. Since v0.10, ESC1/2/3/9 (enrollee) and ESC4/5 (template/CA writer) also feed the graph as `ADCS_ESC` edges to the domain node.

### v0.7 GPP cpassword recovery (`KestrelGPP.c`)

Walks SYSVOL over SMB and parses every Group Policy Preferences XML (Groups, Services, ScheduledTasks, DataSources, Drives, Printers) for `cpassword` - credentials AES-encrypted with the key Microsoft published in 2014 (MS14-025). Any domain user can recover them, so they are decrypted and shown (with the account and GPO) to prove recoverability and force rotation. Largely legacy, but old values persist on SYSVOL for years. Same footprint as the policy audit (an SMB read of SYSVOL). Plaintext buffers are scrubbed with `SecureZeroMemory`.

### v0.8 Default-ACL baseline (`KestrelBaseline.c`)

Not a scan but a filter for the ACL module. It builds a baseline of "expected" ACEs from two authoritative, ordinary-user, pure-LDAP sources - each `classSchema`'s `defaultSecurityDescriptor`, and the `AdminSDHolder` DACL (for `adminCount=1` objects) - then suppresses object ACEs that match it. What remains is the set of genuine, admin-introduced delegations, not the rights every object inherits at birth. `--acl-raw` turns it off to show the raw set.

## Roadmap

| Version | Status | Description                                                                 |
| ------- | ------ | --------------------------------------------------------------------------- |
| v0.1    | ✅      | Six passive AD scans                                                        |
| v0.2    | ✅      | ACL edge extraction + DCSync rights                                         |
| v0.3    | ✅      | Transitive group membership via LDAP\_MATCHING\_RULE\_IN\_CHAIN             |
| v0.4    | ✅      | In-memory graph from ACL + membership + delegation. HTML / JSON / YAML.     |
| v0.5    | ✅      | BFS path finder + GPO security policy audit                                 |
| v0.6    | ✅      | Kerberoastable + AS-REP Roastable detection                                 |
| v0.7    | ✅      | Trust posture · gMSA password readers · ADCS ESC1-5/9 · GPP cpassword       |
| v0.8    | ✅      | Default-ACL baseline (delegation noise suppression) · Onelogon detection    |
| v0.9    | ✅      | LAPS health anomalies · SMB signing (NTLM relay) · Anonymous LDAP posture · description leak scan |
| v0.10   | ✅      | MAQ + RBCD weaponizability · cross-forest RBCD (foreign SID) · dangerous User Rights + built-in groups (operators / DnsAdmins) · Trust/ADCS graph edges · replication-metadata provenance |
| v0.11   | ✅      | BloodHound CE OpenGraph export · diff-over-time on JSON snapshots · single-attribute provenance (ACL / RBCD / shadow-cred) · shadow-credential detection (`msDS-KeyCredentialLink`) |
| v0.12   | ✅      | SID-history edges + injection classification · orphaned adminCount (AdminSDHolder) · trust-account AuthN Policy check (Server 2025 one-way-trust weakness) |
| v0.13   | ✅      | **Entry-condition posture** — domain password policy + Fine-Grained PSOs (spray-friendliness) · krbtgt password age (Golden Ticket exposure) · noPac / Certifried surfacing from MachineAccountQuota |
| v0.14   | ✅      | **ACL depth + lateral edges** — fine-grained dangerous ACEs (`ForceChangePassword` / `WriteSPN` / `AddKeyCredentialLink` / `AddSelf`) · GPO→lateral edges (`AdminTo` / `CanRDP` / `CanPSRemote` / `ExecuteDCOM`) · password-hygiene triad (`PASSWD_NOTREQD` / `DONT_EXPIRE_PASSWORD` / description passwords) |
| v0.15   | ✅      | **ACL structure audit (ADeleg-class)** — owner ≠ admin · disabled inheritance · non-canonical DACL · orphaned trustees · low-priv → Tier-0 aggregation · schema `defaultSecurityDescriptor` backdoor |
| v0.16   | 🔲      | **Stealth persistence + SYSVOL/ADCS depth** — hidden-object / OWNER RIGHTS (`S-1-3-4`) deny-ACE persistence · unattend.xml + SYSVOL secret sweep · ADCS persistence (template validity + NTAuth store) |
| v0.17   | 🔲      | **Cross-domain + hybrid footprint** — foreign security principals in privileged groups · Entra Connect (`MSOL_` / `AAD_`) Tier-0 tagging · ADFS DKM key ACL (Golden SAML precondition) |
| v0.18   | 🔲      | **Query hygiene + honest footprint** — minimal `SDflags` / security-mask · attribute-list & filter-indexability audit · "Detection footprint" documentation (how each scan appears in event 1644) |
| v1.0    | 🔲      | Feature-complete for the on-prem, directory-side posture mission |
| post-1.0 | 🔲     | ADExplorer `.dat` snapshot as an offline input source (optional; touches the data-source layer) |

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
