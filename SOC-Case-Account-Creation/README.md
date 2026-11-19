# SOC Case — Backdoor Local Account Creation (Masqueraded Service Account)

**Week:** 1 — Windows Fundamentals
**Lab:** Attacker (`192.168.100.106`, `BUTCH`) → Windows 10 Home (`192.168.100.108`, agent `winhome01` / `DESKTOP-F0JVTQT`), detected by Wazuh SIEM (`192.168.100.102`) with Sysmon + Security auditing
**ATT&CK:** T1136.001 (Create Account: Local Account), T1098.007 (Account Manipulation: Add Additional Local or Domain Groups — Sysmon-tagged), T1078 (Valid Accounts), T1036 (Masquerading — service-account name)
**Severity:** **High** — persistent backdoor admin account created and confirmed functional (`Pwn3d!`)
**Status:** ✅ Completed (2026-10-31)

## Case Structure

| File | Contents |
|---|---|
| `01-Scenario.md` | Background, audit config |
| `02-Attack-Simulation.md` | Kali step-by-step (psexec → net user /add → add to Administrators → backdoor login test) |
| `03-Alert.md` | Events detected: 4720, 4732, Sysmon 1 (net.exe ×2) |
| `04-Indicators.md` | IOCs: account name, SID, command lines, hashes, group membership |
| `05-Investigation.md` | Triage in Wazuh + evidence list (exact filenames) |
| `06-Timeline.md` | Real event timeline |
| `07-Analysis.md` | Persistence via backdoor account, masquerading, detection gaps |
| `08-Conclusion.md` | Findings, severity, lessons |
| `09-Remediation.md` | Hardening + custom Wazuh rule |
| `evidence/` | 9 screenshots (filenames listed below) |
| `kali-commands.txt` | Exact commands run |

## Evidence screenshots (exact filenames — place in `evidence/`)

| Filename | Content |
|---|---|
| `1-kali-psexec-shell.png` | impacket-psexec SYSTEM shell (uploaded `DmmYUPVU.exe`, service `Wlug`) |
| `02-kali-net-user-add.png` | `net user svc_backup ... /add` → success |
| `03-kali-add-to-administrators.png` | `net localgroup Administrators svc_backup /add` → success |
| `04-kali-verify-account.png` | `net user svc_backup` + `net localgroup Administrators` (account active, never expires, in Administrators) |
| `05-kali-backdoor-login-test.png` | `netexec smb` as `svc_backup` → `(Pwn3d!)` — backdoor confirmed |
| `07-wazuh-4720-account-created.png` | Wazuh Event ID 4720 JSON (svc_backup, SID -1011, subject SYSTEM) |
| `08-wazuh-4732-added-to-admins.png` | Wazuh Event ID 4732 JSON (svc_backup added to Administrators, S-1-5-32-544) |
| `10-wazuh-sysmon-1-net-exe.png` | Wazuh Sysmon Event ID 1 — two `net.exe` process creations (full command lines + hashes) |
| `12-windows-eventviewer-4720-4732.png` | Windows Event Viewer — Security log filtered 4720/4732, 4732 details panel |

## Result Summary (actual, from evidence)

- **Foothold:** `impacket-psexec v0.14.0` (adminlab) → SYSTEM shell (uploaded `DmmYUPVU.exe`, service `Wlug`). Windows 10 Build 19045.2846.
- **Backdoor account created:** `svc_backup` / `B@ckupSvc2026!`, full name "Backup Service Account", comment "Service account for automated backup", account expires **Never** (masqueraded as a service account). SID: `S-1-5-21-1384641147-1165911532-2121891537-1011`.
- **Added to Administrators:** `net localgroup Administrators svc_backup /add` → success. Verified in `net user` output: Local Group Memberships `*Administrators *Users`.
- **Backdoor confirmed functional:** `netexec smb 192.168.100.108 -u svc_backup -p 'B@ckupSvc2026!'` → `(Pwn3d!)` — persistent admin access.
- **Detection (3 layers):**
  - **Event ID 4720** (Security) — "A user account was created", subject = `DESKTOP-F0JVTQT$` (SYSTEM, S-1-5-18), target `svc_backup`, SID -1011.
  - **Event ID 4732** (Security) — "A member was added to a security-enabled local group": member SID -1011 (svc_backup) → group `Administrators` (S-1-5-32-544, Builtin). systemTime 2026-10-31T15:53:39.245Z, eventRecordID 4390.
  - **Sysmon Event ID 1** — two `net.exe` (32-bit, SysWOW64) process creations with full command lines, hashes captured, parent `cmd.exe` (psexec), user SYSTEM. The `net localgroup` event auto-tagged **T1098.007 Add-Additional Local or Domain Groups** (SwiftOnSecurity).
