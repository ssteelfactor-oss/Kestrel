# Kestrel — Detection Footprint

Kestrel is built to be **detectable by design**. It is read-only, uses ordinary
domain-user rights, native LDAP over the normal DC ports, and no evasion. This
document is an honest, complete account of the trace Kestrel leaves so that a
defender can see it, whitelist it, or tell it apart from an attacker — without
reverse-engineering the binary.

Nothing here is obfuscation guidance. It is the opposite: the more precisely a
blue team knows what Kestrel does on the wire and in the logs, the better.

---

## The one-line version

Kestrel **reads**. It never writes. So it can only ever produce read/access
events (LDAP searches, property reads, SYSVOL file reads). It can **never**
produce a directory-modification event, because it never modifies the directory.

---

## What Kestrel never generates

Because every operation is a read, none of the following can come from Kestrel.
If you see these, they are not Kestrel:

| Event | Meaning |
|-------|---------|
| 5136 | A directory object was modified |
| 5137 / 5138 / 5139 / 5141 | Object created / undeleted / moved / deleted |
| 4720 / 4722 / 4725 / 4726 / 4738 | Account created / enabled / disabled / deleted / changed |
| 4728 / 4729 / 4732 / 4733 / 4756 / 4757 | Member added to / removed from a group |
| 4670 | Permissions on an object were changed |
| 4724 / 4723 | Password reset / change |

Kestrel writes no ACEs, adds no members, resets no passwords, plants nothing. A
correct run changes the directory in exactly zero ways.

---

## Kestrel is not DCSync

This is the distinction that matters most for a blue team. Kestrel enumerates
delegation (DCSync rights, RBCD, shadow credentials, ACL edges) by **reading
`nTSecurityDescriptor` and normal attributes over LDAP** — it does **not**
replicate the directory.

- No DRSUAPI / `IDL_DRSGetNCChanges` call is ever made.
- The DS-Replication-Get-Changes / -All extended rights are **detected**, never
  **used**.
- Security descriptors are read with a **DACL-only** security mask
  (`ADS_SECURITY_INFO_DACL`), so Kestrel never requests the SACL and never needs
  `SeSecurityPrivilege`.

Consequently Kestrel does **not** produce the DCSync signature — event **4662**
carrying the replication property-set GUIDs `1131f6aa-…` / `1131f6ad-…`. A tool
that reads *who can* DCSync looks nothing, on the wire, like a tool that *does*
DCSync. This is the whole point of an auditor.

---

## What Kestrel does generate

All of the below are conditional on the DC actually having the corresponding
auditing turned on. On a default-audit DC most of these are silent.

### Event 1644 — expensive / inefficient LDAP search
Fires only when the DC has search-statistics logging enabled (the `15 Field
Engineering` diagnostic level, or the *Expensive*/*Inefficient Search Results
Threshold* registry values). Kestrel's filters lead with **indexed** clauses
(`objectClass`, `objectCategory`, `objectSid`, `sAMAccountName`, `adminCount`),
so the trigger, where it exists, is **result-set size** on the full-domain
enumerations (the ACL and hygiene passes), not a non-indexed filter. All searches
are paged (`ADS_SEARCHPREF_PAGESIZE`).

### Event 4662 — operation on a directory object
Fires when *Audit Directory Service Access* is on **and** the target object has a
SACL that audits the read. Reading `nTSecurityDescriptor` and object properties
on a SACL'd object produces 4662 — but with the **object's own** access mask, not
the replication GUIDs (see above). Putting audit-read SACLs on your Tier-0
objects is, in fact, the cleanest way to see Kestrel (and real attackers) reading
them.

### Event 4661 — a handle to a SAM/DS object was requested
Same preconditions as 4662, for SAM-class objects.

### Events 5145 / 4663 — network-share / file access (SYSVOL)
The SYSVOL-facing scans (`--gpp`, `--policy`, `--gpolateral`, and the SYSVOL leg
of `--trust`) read files under `\\<domain>\SYSVOL` over SMB. With file-share or
object-access auditing enabled, these appear as share/file reads of `GptTmpl.inf`,
GPP XML, answer files, and scripts. Files are capped at 1 MB and recursion is
bounded.

### Authentication
Each LDAP bind authenticates like any domain tool (4624 at the DC). There is
nothing Kestrel-specific here.

---

## Per-scan catalog

Scope key: **B** = base (one object), **1** = one-level, **S** = subtree.
"SD" = reads `nTSecurityDescriptor` (DACL-only mask). "SMB" = reads SYSVOL files.

| Flag | Primary LDAP filter(s) | Scope | SD | SMB | Dominant trace |
|------|------------------------|:----:|:--:|:---:|----------------|
| `--acl` | object classes across the domain NC; domain-head base read (reanimate) | S/B | ✔ | | 4662 on SACL'd objects; 1644 by result size |
| `--groups` | `(&(objectClass=group)(objectSid=…))`, `LDAP_MATCHING_RULE_IN_CHAIN` | B/S | | | indexed; low |
| `--adminsdholder` | `(adminCount=1)` | S | ✔ | | indexed |
| `--sidhistory` | user/group read of `sIDHistory` | B/S | | | indexed |
| `--pwdpolicy` | domain root, PSO container, `(sAMAccountName=krbtgt*)` | B/1/S | | | indexed; small |
| `--hygiene` | `(&(objectCategory=person)(objectClass=user))` | S | | | 1644 by result size |
| `--roast` | SPN / `DONT_REQ_PREAUTH` UAC bit accounts | S | | | indexed lead |
| `--shadowcreds` | `msDS-KeyCredentialLink` readers | S | | | indexed lead |
| `--delegation` | UAC delegation bits + `msDS-AllowedToActOnBehalfOf…` | S | | | indexed lead |
| `--schema` | `(objectClass=classSchema)` in the Schema NC | 1 | | | indexed |
| `--trust` | `(objectClass=trustedDomain)` + SYSVOL | S | | ✔ | indexed; 5145 |
| `--gmsa` | `(objectClass=msDS-Group-Managed-Service-Account)` | S | | | indexed |
| `--adcs` | `pKICertificateTemplate`, `pKIEnrollmentService`, `(cn=NTAuthCertificates)` in Config NC | S | ✔ | | indexed; 4662 |
| `--adfs` | `(&(objectClass=contact)(thumbnailPhoto=*))` under `CN=Microsoft,CN=Program Data` | S | ✔ | | indexed lead; small |
| `--gpp` | — (pure SYSVOL sweep) | — | | ✔ | 5145 / 4663 |
| `--gpolateral` | `(objectClass=groupPolicyContainer)`, `(objectClass=computer)` + SYSVOL | S | | ✔ | indexed; 5145 |
| `--policy` | GPO objects + SYSVOL (`GptTmpl.inf`) | 1/S | | ✔ | indexed; 5145 |
| `--topology` | `(objectClass=nTDSService)`, computer SPNs | S | | | indexed |
| `--adws` | — (TCP connect to 9389 per DC) | — | | | connection only |

The `msDS-Repl*MetaData` provenance reads (`KestrelProvenance.c`) are **base-scope,
single-object**, targeted at the specific high-value object being explained — the
smallest possible footprint, and readable by anyone who can read the object
(*not* gated by DCSync).

---

## For defenders: how to actually see it

1. **Put audit-read SACLs on Tier-0** (Domain Admins, the AdminSDHolder, the
   `CN=NTAuthCertificates` object, the AD FS DKM contact object, GPO objects).
   Kestrel's SD and property reads then surface as 4662 — and so do a real
   attacker's.
2. **Turn on directory-service and file-share auditing** on DCs, and, if you want
   the LDAP query view, enable expensive/inefficient search logging (event 1644)
   in a test window.
3. **Watch SYSVOL reads** of `GptTmpl.inf`, GPP XML, `unattend`/`sysprep`, and
   `.ps1`/`.bat` from a single principal in quick succession — that shape is the
   `--gpp`/`--policy` sweep.

## For defenders: how to tell Kestrel from an attacker

The trace shape overlaps with recon tooling — that is unavoidable for any auditor,
and Kestrel does not try to hide it. The distinguishing facts are behavioural:

- **Read-only.** Correlate the read burst with the modification events above. An
  auditor produces none of them; post-exploitation almost always produces some.
- **No replication.** No DRSUAPI/`GetNCChanges`, so no DCSync-signature 4662.
- **Ordinary rights.** No privilege escalation, no `SeSecurityPrivilege`
  (DACL-only SD reads), no SACL requests.
- **Honest volume.** Paged, indexed-led queries and bounded SYSVOL reads — no
  attempt to spread reads out to stay under a threshold.

If you run Kestrel yourself on a schedule, the simplest disambiguation is to
whitelist the account and host you run it from, and treat the same read shape
from anywhere else as worth a look.
