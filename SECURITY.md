# Security Policy

## What Kestrel is

Kestrel is a **defensive** Active Directory auditing tool. It is read-only, runs
with ordinary domain-user rights, performs no evasion, and its trace on a domain
controller is documented in [FOOTPRINT.md](FOOTPRINT.md).

Use it only against directories you own or are explicitly authorised to audit.

## Supported versions

Kestrel is pre-1.0 and moves fast. Security fixes land on `main`; there are no
backports to earlier tags. If you are running an older build, update before
reporting.

| Version | Supported |
|---------|-----------|
| `main` / latest tag | ✅ |
| older tags | ❌ |

## Reporting a vulnerability

Please report privately, **not** as a public issue:

- Preferred: **GitHub → Security → Report a vulnerability** (private advisory).
- Include: affected version/commit, what you did, what happened, and — if the bug
  involves parsing — the input that triggers it.

This is a single-maintainer project. Expect acknowledgement within a few days and
an honest estimate rather than a fixed SLA. If a report is valid and you would
like credit, say so and you will be credited in the fix.

## Design invariants — a violation is a security bug

Kestrel makes a small number of hard promises. These are not stylistic
preferences; users rely on them when they decide it is safe to run this in
production. **If you can demonstrate a violation of any of these, that is a
security vulnerability and I want to hear about it:**

1. **Read-only.** Kestrel never writes to the directory. Any code path that
   creates, modifies, moves, or deletes a directory object — or writes to SYSVOL —
   is a bug, no matter how it is reached.
2. **Ordinary domain user.** No privilege escalation, no `SeSecurityPrivilege`,
   no SACL requests. Security descriptors are read with a DACL-only mask.
3. **No replication.** Kestrel detects who *can* DCSync; it never calls DRSUAPI /
   `IDL_DRSGetNCChanges` itself.
4. **Directory and SYSVOL only.** No RPC or SMB reads against non-DC member hosts.
5. **No evasion.** No query fragmentation, timing randomisation, or log tampering.
6. **On-prem only.** No calls to Entra / Graph or any cloud API.
7. **Secrets are not persisted.** Recovered plaintext (for example GPP
   `cpassword`) is printed for the operator and scrubbed from memory; it is never
   written to a report file, a temp file, or a log.

## In scope

Kestrel is written in C and parses data that an attacker may control — SYSVOL
files (`GptTmpl.inf`, GPP XML, answer files, scripts), LDAP attribute values,
SDDL strings, certificate blobs, and key-credential structures. Memory safety in
those parsers is a genuine trust boundary, because a low-privileged user who can
write to SYSVOL or set an attribute can influence Kestrel's input.

Reports are in scope for:

- Memory-safety bugs reachable from parsed input: buffer overflow, out-of-bounds
  read, use-after-free, integer overflow in a length calculation.
- Any violation of the invariants listed above.
- Leaking recovered secrets to disk, logs, or report output.
- Crashes or unbounded resource consumption triggered by hostile input.
- Anything that causes Kestrel to act on, or connect to, a host outside its
  documented scope.

## Out of scope

These are not vulnerabilities in Kestrel:

- **Findings Kestrel reports about your directory.** Those are misconfigurations
  in the audited environment — fix them there. Kestrel finding them is the point.
- **Kestrel being detectable.** That is deliberate; see
  [FOOTPRINT.md](FOOTPRINT.md).
- **Kestrel requiring domain credentials.** It is an authenticated auditor.
- **Missing detections or false positives.** Useful, but please open a normal
  issue rather than a security report.

## Reporting vulnerabilities you find *with* Kestrel

If Kestrel helps you find a flaw in someone else's environment, report it to that
organisation through their disclosure process. If you believe you have found a
flaw in Active Directory or another Microsoft product, report it to the
[Microsoft Security Response Center](https://msrc.microsoft.com/report). Please do
not send those reports here.
