# endpoint-hardening-audit

**Nine read-only checks that tell you whether a workstation is actually hardened.**

Security posture questions get answered by vibes: *is FileVault on? does the screen
actually lock? is anything listening on the network?* This runs the checks and gives
you a table — or JSON, if you're collecting across a fleet.

```
$ ./audit.sh
Endpoint Hardening Audit — WKSTN-4417 — 2026-09-10 08:09

RESULT CHECK                        DETAIL
------ ---------------------------- ----------------------------------------
PASS   Disk encryption              FileVault enabled
SKIP   Firewall                     state unreadable without elevated rights
FAIL   Screen lock                  no password required on wake
WARN   Automatic updates            automatic checks disabled or unreadable
WARN   SSH root login               not explicitly set (defaults vary by build)
WARN   Externally bound services    15 listening on all interfaces: node, ssh…
PASS   Guest account                disabled

Summary: 2 pass · 4 warn · 1 fail · 2 skipped
Action required: 1 check(s) failed.
```

## It is read-only, deliberately

This tool **reports**. It does not remediate.

- **No writes.** No `defaults write`, no `systemctl enable`, no config edits.
- **No `sudo`.** Checks that need elevation report `SKIP` rather than escalating.
- **No network connections.** Every check is local.
- **No remediation flag.** There is deliberately no `--fix`. Auto-changing security
  settings on a machine you do not own is how you lock someone out of their own
  laptop. The report tells you what to change; a human decides.

Every check is a query you could run by hand — the point is running all nine
consistently, on every machine, in two seconds.

## Checks

| Check | Looks for |
|---|---|
| Disk encryption | FileVault (macOS) / LUKS volume (Linux) |
| Firewall | Application firewall state, `ufw`, `firewalld`, or `nftables` |
| Screen lock | Password required on wake — **and how long the grace period is** |
| Automatic updates | Update checks enabled / `unattended-upgrades` |
| Remote login | Whether SSH is accepting connections |
| SSH root login | `PermitRootLogin` |
| SSH password auth | `PasswordAuthentication` — keys-only or brute-forceable |
| Externally bound services | Listeners on `0.0.0.0` / `[::]` rather than loopback |
| Guest account | Guest login enabled |

## Three details that matter

**A screen lock with a long grace period isn't a screen lock.** Checking
`askForPassword` alone passes a machine that waits five minutes before actually
locking. The check reads `askForPasswordDelay` too and downgrades anything over a
minute to `WARN`.

**`sshd_config` is last-directive-wins.** A file with `PermitRootLogin yes` at the
top and `PermitRootLogin no` at the bottom is secure, and a naive `grep | head -1`
reports the opposite. The check takes the **last** match.

**Bound to loopback is not the same as listening.** Plenty of tools open ports on
`127.0.0.1`, which no one outside the machine can reach. Only listeners on
`0.0.0.0` or `[::]` are actually exposed, and those are what get counted.

## Usage

```bash
./audit.sh              # table
./audit.sh --json       # machine-readable, for fleet collection
./audit.sh --strict     # exit 1 if any check FAILs — for CI or MDM compliance gates
```

`--strict` makes it usable as a gate: run it from your MDM or a scheduled job and
alert on non-zero exit.

## Platform support

| Platform | Status |
|---|---|
| macOS | Tested on macOS 26 (Apple Silicon) |
| Linux | Supported — `ufw`/`firewalld`/`nftables`, `lsblk`, `systemctl`, `ss` |
| Windows | Not yet. A PowerShell port checking BitLocker, Defender and the local firewall is the obvious next step. |

Some checks return `SKIP` without elevation. That is intentional — a `SKIP` is
honest, a false `PASS` is dangerous.

## License

MIT — see [LICENSE](LICENSE).
