# Kestrel

[![build](https://github.com/ssteelfactor-oss/Kestrel/actions/workflows/build.yml/badge.svg)](https://github.com/ssteelfactor-oss/Kestrel/actions/workflows/build.yml)
[![license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![language](https://img.shields.io/badge/language-C-informational.svg)](#)
[![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](#)

> ### BloodHound shows you the path. Kestrel shows you what's already inside.

Everyone maps the same thing: the attack path - *who can reach Domain Admin.* It's the right question, and the tools that answer it are excellent. But a graph of "who can reach whom" is blind to an entire class of problem, because some of the worst things in an Active Directory aren't a path at all.

They're a backdoor welded into an attribute. A certificate that keeps authenticating long after the password is reset. A permission stamped into the schema itself, so every object created from now on inherits it silently. A deleted account someone quietly kept the right to bring back. An object hidden from enumeration by a single deny-read ACE.

**None of that is an edge in a graph. All of it is sitting in your directory right now.** Kestrel reads it - with native Windows calls, ordinary domain-user rights, no server, no Python, no agent, and a footprint on the domain controller so restrained it's [documented event-by-event](FOOTPRINT.md).

One `.exe`. One command. Everything below.

---

## You've been looking the wrong way

The offensive AD ecosystem - SharpHound, impacket, Certipy, and the graph behind them - is superb, and it all looks at the same surface: reachability. Kestrel looks at the three dimensions that surface can't express.

- **Time.** A graph is a snapshot. Kestrel reads replication metadata - *when* a Tier-0 attribute changed and *which DC* originated it. A DCSync right granted last night is not the same finding as one that's been there for years, and only one of them means you're being attacked right now.
- **Persistence in an attribute, not an edge.** Shadow credentials, SID history, reanimate-tombstones, schema `defaultSecurityDescriptor` backdoors, hidden objects, `OWNER RIGHTS` deny-ACEs, AD FS DKM keys. The graph tools don't collect these because there's no edge to draw.
- **Defensive posture, inverted.** Not "who can attack," but "what isn't protected" - the Tier-0 account outside its silo, the sync account with a random RID that nobody tagged, the lockout policy that never throttles a spray.

It's not that Kestrel is faster than a graph. It answers questions the graph can't ask.

---

## Every AD sin, in one native exe

| Sin | What Kestrel finds | Flag(s) |
|-----|-------------------|---------|
| **Replication & delegation** | DCSync rights (who *can* replicate - without ever replicating), unconstrained / constrained / RBCD / S4U delegation | `--acl` · `--delegation` |
| **Certificate abuse** | AD CS ESC1–5/9, rogue CA in the NTAuth store, long-lived cert persistence, **AD FS DKM key ACL - the Golden SAML precondition** | `--adcs` · `--adfs` |
| **Persistence in attributes** | Shadow credentials, SID history injection, **tombstone-reanimation rights**, **hidden objects**, **schema `defaultSecurityDescriptor` backdoors**, orphaned `adminCount` | `--shadowcreds` · `--sidhistory` · `--acl` · `--schema` · `--adminsdholder` |
| **Cleartext & crackable creds** | GPP `cpassword`, `unattend`/`sysprep` secrets and script passwords across SYSVOL, Kerberoastable and AS-REP-roastable accounts, LAPS coverage gaps | `--gpp` · `--roast` · `--laps` |
| **Cross-domain & hybrid** | Foreign principals in privileged groups, **Entra Connect sync accounts tagged Tier-0**, trust posture, **machine accounts created via MachineAccountQuota** (`mS-DS-CreatorSID`) | `--groups` · `--trust` · `--machines` |
| **Posture & recon** | Password / PSO policy, `krbtgt` age, LLMNR / NBT-NS / WDigest / NTLMv1 GPO settings, gMSA readers, stale computers, delegation topology | `--pwdpolicy` · `--policy` · `--gmsa` · `--stale` |
| **Archaeology** | **Orphaned dangerous ACEs** (a right held by a deleted principal - the SID resolves to nobody), **stale privileged accounts** (forgotten, over-privileged, ancient password) | `--archaeology` |
| **Domain hardening** | `dSHeuristics` anonymous-LDAP / AdminSDHolder-exclusion flags, Pre-Windows 2000 Compatible Access broad membership | `--hardening` |
| **Service posture** *(read from AD, no packet to the service)* | **Exchange-to-DA escalation & EOL**, **SCCM container takeover & site map**, **ADIDNS zone poisoning** (Authenticated Users can create records) | `--exchange` · `--sccm` · `--dns` |

Two dozen-plus checks that are usually spread across a dozen scripts and two languages. Here they're one binary - and they end in a single, severity-sorted verdict.

---

## One line

```
Kestrel.exe --all --report audit.html
```

Run everything. Get the full HTML report. And, at the very end of the console, the part that matters:

```
═══ Kestrel - Prioritized Findings ═══

  CRITICAL  DCSync         CORP\svc_sql - non-default principal can replicate directory changes (DCSync)
                          → fix: remove GetChanges/GetChangesAll from the principal on the domain head (dsacls) unless it is a DC
  CRITICAL  AD FS          CN=... - read access to the DKM key (Golden SAML precondition)
                          → fix: remove non-default read ACEs on the DKM object (dsacls) and rotate the token-signing certificate
  HIGH      Persistence    CN=... - object hidden from enumeration via a broad deny-read ACE
                          → fix: inspect the hidden object and remove the broad deny-read ACE (dsacls)

  [=] 2 critical · 1 high · 0 medium · 0 low
```

Not a wall of output. The findings that matter, ranked, each with the command to close it.

---

## One exe. Red, blue, purple.

- **Red / grey** - enumerate persistence and delegation the graph misses, export straight to BloodHound CE OpenGraph (`--opengraph`) to fuse with your existing collection, or pivot from any principal (`--from`).
- **Blue** - a prioritized, remediated findings list; a `--diff` against last week's snapshot to catch what *changed*; and a tool whose exact detection footprint is published so you can whitelist it and tune your own alerting around it.
- **Purple** - one artifact both sides read the same way. Red finds it, blue fixes it, everyone points at the same line number.

## Detectable by design

Kestrel is read-only. It never writes to the directory, never replicates, never needs `SeSecurityPrivilege`, never touches the cloud. Reading *who can* DCSync looks nothing, on the wire, like *doing* DCSync - no DRSUAPI, no replication-signature `4662`. Every query it runs and every event it can (and cannot) generate is catalogued in **[FOOTPRINT.md](FOOTPRINT.md)**. An auditor that tells the defender exactly how to catch it isn't a contradiction - it's the whole point.

---

## Quick start

**Grab a build.** Every green CI run publishes a `Kestrel.exe` artifact - download it from the [Actions tab](https://github.com/ssteelfactor-oss/Kestrel/actions), no toolchain required.

**Or build it yourself.** Visual Studio (v143+) or MSBuild:

```
git clone https://github.com/ssteelfactor-oss/Kestrel.git
cd Kestrel
msbuild Kestrel.vcxproj /p:Configuration=Release /p:Platform=x64
```

Pure C, zero third-party dependencies. Build `/MT` and it's a single self-contained executable - drop it on a domain-joined host, run as any ordinary user.

**Run it.**

```
Kestrel.exe --all --report audit.html      # everything, HTML report + ranked findings
Kestrel.exe --acl --adcs --adfs            # pick specific checks
Kestrel.exe --paths --from CORP\jdoe       # attack paths from one principal
Kestrel.exe --all --diff last-week.json    # what changed since the last snapshot
Kestrel.exe --all --opengraph graph.json   # export to BloodHound CE OpenGraph
```

---

## Modules

Run `--all`, or select any subset. Full help: `Kestrel.exe --help`.

| Flag | Scan |
|------|------|
| `--acl` | ACL edges, DCSync rights, owner/inheritance/canonical hygiene, hidden objects, reanimate-tombstones |
| `--groups` | Transitive privileged membership + foreign security principals |
| `--delegation` | Unconstrained / constrained / RBCD / S4U2Self |
| `--paths` / `--from` | Attack-path analysis to Tier-0 (optionally from a given principal) |
| `--adcs` | AD CS certificate-template / CA audit (ESC1–5/9) + NTAuth store + validity |
| `--adfs` | AD FS DKM key ACL (Golden SAML precondition) |
| `--schema` | Schema `defaultSecurityDescriptor` backdoor audit |
| `--trust` | Domain / forest trust posture |
| `--machines` | Machine accounts created via MachineAccountQuota (`mS-DS-CreatorSID`) |
| `--roast` | Kerberoastable + AS-REP-roastable accounts |
| `--shadowcreds` | Shadow credentials (`msDS-KeyCredentialLink`) |
| `--sidhistory` | `sIDHistory` injection (privileged / foreign) |
| `--adminsdholder` | Orphaned `adminCount=1` objects |
| `--gpp` | SYSVOL secret sweep - GPP `cpassword`, `unattend`, script creds |
| `--gpolateral` | GPO local-group → lateral edges (AdminTo / CanRDP / CanPSRemote / ExecuteDCOM) |
| `--policy` | GPO security policy (LLMNR / NBT-NS / WDigest / NTLMv1) |
| `--pwdpolicy` | Password / PSO policy · `krbtgt` age · MachineAccountQuota |
| `--hygiene` | Credential hygiene (`PASSWD_NOTREQD` / `DONT_EXPIRE` / reversible / description leaks) |
| `--gmsa` | gMSA password-reader enumeration |
| `--laps` | LAPS coverage (legacy + Windows LAPS 2023+) |
| `--stale` | Stale computers via `lastLogonTimestamp` |
| `--topology` | Computer topology via SPN decoding |
| `--adws` | ADWS endpoint detection (9389/TCP per DC) |
| `--archaeology` | Orphaned dangerous ACEs (dead owner, live right) + stale privileged accounts |
| `--hardening` | Domain hardening flags: `dSHeuristics` anon-access / SDProp exclusion + Pre-Windows 2000 Compatible Access |
| `--exchange` | Exchange posture: version/EOL + Exchange-to-DA escalation (WriteDACL on the domain) *(service; opt-in)* |
| `--sccm` | SCCM/MECM posture: `System Management` container ACL + management-point / site map *(service; opt-in)* |
| `--dns` | AD-integrated DNS (ADIDNS): zone CreateChild DACL + wpad/isatap/wildcard + DnsAdmins *(service; opt-in)* |

**Service posture** (`--exchange` · `--sccm` · `--dns`) is opt-in and **not** part of `--all`; run `--services` for the whole layer. Findings now carry **MITRE ATT&CK** technique tags.

**Output & interop:** `--report <file>` (`.html` / `.json` / `.yaml`) · `--opengraph <file>` (BloodHound CE) · `--diff <snapshot.json>` · `--verbose`.

---

## Design invariants

These are promises, not preferences - the reasons it's safe to run in production. Breaking any of them is a security bug (see [SECURITY.md](SECURITY.md)).

- **Read-only** - never creates, modifies, or deletes a directory object. Only read/access events, never modification events.
- **Ordinary domain user** - no privilege escalation, no `SeSecurityPrivilege`, DACL-only security masks.
- **No replication** - detects who *can* DCSync; never calls DRSUAPI itself.
- **Directory & SYSVOL only** - no RPC/SMB against member hosts.
- **No evasion** - no query fragmentation, no timing games, no log tampering. See [FOOTPRINT.md](FOOTPRINT.md).
- **On-prem only** - no Entra / Graph / cloud calls; it audits the footprint hybrid leaves *in AD*.
- **Native & self-contained** - pure C, zero third-party dependencies, single `.exe`.

---

## Roadmap

| Version | Status | Milestone |
|---------|:------:|-----------|
| v0.13   | ✅ | Entry-condition posture |
| v0.14   | ✅ | ACL depth + lateral edges |
| v0.15   | ✅ | ACL structure audit (ADeleg-class) |
| v0.16   | ✅ | Stealth persistence + SYSVOL / ADCS depth |
| v0.17   | ✅ | Cross-domain + hybrid footprint |
| v0.18   | ✅ | Query hygiene + honest footprint |
| **v1.0** | ✅ | **Feature-complete: prioritized findings + remediation, CI, Apache 2.0** |
| **v1.1** | ✅ | **Passive service-posture layer: Exchange · SCCM · ADIDNS · domain hardening · MITRE ATT&CK tags** |
| **v1.2** | ✅ | **AD archaeology: orphaned dangerous ACEs + stale privileged accounts** |
| v1.3    | 🔲 | Hybrid seam (Entra Connect / Seamless SSO) · nTDSConnection / DCShadow precondition |

---

## Documentation

- **[FOOTPRINT.md](FOOTPRINT.md)** - the exact LDAP / SYSVOL trace each scan leaves, and the DC events it does (and can't) generate.
- **[SECURITY.md](SECURITY.md)** - reporting, scope, and the design invariants as verifiable guarantees.
- **[LICENSE](LICENSE)** - Apache 2.0.

## Related

Parent project: [NetEnum](https://github.com/ssteelfactor-oss/NetEnum) - AD enumeration via ADSI / COM / LDAP.

## Author

[@ssteelfactor-oss](https://github.com/ssteelfactor-oss) - security research and COM / Windows internals.

## License

Licensed under the **Apache License 2.0** - see [LICENSE](LICENSE). Provided "as is", without warranty; run it only against directories you're authorised to audit.
