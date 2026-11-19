# 03 — Alert / Detection (actual events)

Three detection layers fired. Agent `winhome01` (192.168.100.108).

## 1. Windows Event ID 4720 — User Account Created (money shot #1)

Channel: Security. Full JSON in Wazuh:

| Field | Value |
|---|---|
| `eventID` | **4720** — "A user account was created." |
| `subjectUserName` / `subjectUserSid` | `DESKTOP-F0JVTQT$` / `S-1-5-18` (**SYSTEM** — created from psexec SYSTEM shell; not a user account — suspicious) |
| `subjectDomainName` / `subjectLogonId` | `WORKGROUP` / `0x3e7` |
| `targetUserName` / `samAccountName` | `svc_backup` |
| `targetSid` | `S-1-5-21-1384641147-1165911532-2121891537-1011` (new account) |
| `targetDomainName` | `DESKTOP-F0JVTQT` |
| `primaryGroupId` | 513 (Users) |
| `userAccountControl` | `%%2080 %%2082 %%2084` (normal-account flags) |
| `accountExpires` | never (`/expires:never`) |
📸 `evidence/07-wazuh-4720-account-created.png`

**Why it's suspicious:** account created by **SYSTEM/machine context** (subject = machine account), not by an interactive admin — typical of post-execution tooling (psexec).

## 2. Windows Event ID 4732 — Member Added to Security-Enabled Local Group (money shot #2)

| Field | Value |
|---|---|
| `eventID` | **4732** — "A member was added to a security-enabled local group." |
| `targetUserName` (group) | `Administrators` |
| `targetSid` / `targetDomainName` | `S-1-5-32-544` (well-known Administrators) / `Builtin` |
| `memberSid` | `S-1-5-21-1384641147-1165911532-2121891537-1011` (**matches svc_backup's SID from 4720** — correlation!) |
| `subjectUserName` / `subjectSid` | `DESKTOP-F0JVTQT$` / `S-1-5-18` (SYSTEM) |
| `systemTime` | `2026-10-31T15:53:39.2458365Z` |
| `eventRecordID` / `processID` | 4390 / 668 |
| `severityValue` | AUDIT_SUCCESS |
📸 `evidence/08-wazuh-4732-added-to-admins.png`

**Correlation:** member SID in 4732 (-1011) = target SID in 4720 (svc_backup) → the newly created account was immediately added to Administrators = backdoor.

## 3. Sysmon Event ID 1 — Process Create (two net.exe events, side by side)

Both `net.exe` invocations captured (32-bit, `C:\Windows\SysWOW64\net.exe`), parent `C:\Windows\SysWOW64\cmd.exe` (psexec-spawned), user `NT AUTHORITY\SYSTEM`, integrityLevel System:

| | Left panel (account create) | Right panel (admin add) |
|---|---|---|
| `commandLine` | `net user svc_backup "B@ckupSvc2026!" /add /fullname:"Backup Service Account" /comment:"Service account for automated backup" /expires:never` | `net localgroup Administrators svc_backup /add` |
| `processId` / `parentProcessId` | 12436 / 13176 | 1568 / 13176 |
| `utcTime` | 2026-10-30 14:52:14.298Z | 2026-10-31 15:53:37.056Z |
| `ruleName` (Sysmon tag) | (account-creation technique) | **technique_id=T1098.007, technique_name=Add-Additional Local or Domain Groups** |

Common: hashes SHA1=`A5BAD2CDD4BAEDB590A3646F7248BF060A2F13`, MD5=`31890A7DE89936F922D44D677F681A7C`, SHA256=`70C4C725E266F12ABAC850FD1598D4001201BCA8E7ACA901508307E365AFFF42`, IMPHASH=`A59258B3BCAE410F6DBF53F9767`; fileVersion 10.0.19041.1; company Microsoft Corporation.
📸 `evidence/10-wazuh-sysmon-1-net-exe.png`

## Corroboration (Windows Event Viewer)

Security log → filter Event IDs **4720, 4732** → **32 events** (includes earlier test accounts). This case's events: **4720 at 10/30/2026 7:52:15 AM** (User Account Management), **4732 at 10/31/2026 8:53:39 AM** (Security Group Management). 4732 details panel: Member = `DESKTOP-F0JVTQT\svc_backup`, Logon ID `0x3E7`, Audit Success.
📸 `evidence/12-windows-eventviewer-4720-4732.png`

## Detection gap note

Built-in Wazuh rules alert on 4720/4732 but typically at low/medium severity; a **new account immediately added to Administrators** is the high-severity correlation. Custom rule in `09-Remediation.md` (4720 followed by 4732 within short window, or 4732 adding a recently-created SID) closes this.
