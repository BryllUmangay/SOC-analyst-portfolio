# 01 — Scenario

## Background

An attacker with local-admin credentials (`adminlab`, obtained in earlier cases) gains a SYSTEM shell on `winhome01` via `impacket-psexec`. To establish **persistence that survives password resets and reboots**, they create a backdoor local account **masquerading as a service account** (`svc_backup`, "Backup Service Account"), set it to never expire, and add it to the local Administrators group. They then verify the backdoor works by authenticating as `svc_backup` from Kali. Target has Sysmon (SwiftOnSecurity) and default Security auditing (user-account management auditing is on by default — 4720/4732 need no special config). Wazuh forwards Security + Sysmon channels.

## Target

- `DESKTOP-F0JVTQT` / `winhome01` / `192.168.100.108`, Windows 10 Build 19045.2846 (22H2), workgroup.
- Attacker: `192.168.100.106` (BUTCH).

## Snapshot before attack: `winhome01-baseline-clean`.

## Evidence for this stage
- `evidence/1-kali-psexec-shell.png` — foothold shell.
