# 04 — Indicators (IOCs, actual)

## Account IOCs (the persistence object)

| Indicator | Value |
|---|---|
| Account name | `svc_backup` (masquerades as backup service account — T1036) |
| Full name / comment | "Backup Service Account" / "Service account for automated backup" |
| Password | `B@ckupSvc2026!` (lab — rotate/delete) |
| SID | `S-1-5-21-1384641147-1165911532-2121891537-1011` |
| Account expires | **Never** (`/expires:never`) |
| Group memberships | **Administrators** (S-1-5-32-544) + Users (513) |
| Created by | `DESKTOP-F0JVTQT$` (SYSTEM, S-1-5-18) — machine context, not a user |
| Creation method | `net.exe /add` (32-bit, SysWOW64) from psexec-spawned `cmd.exe` |

## Process / hash IOCs (Sysmon Event ID 1)

| Indicator | Value |
|---|---|
| Image | `C:\Windows\SysWOW64\net.exe` (32-bit) |
| Parent | `C:\Windows\SysWOW64\cmd.exe` (psexec) |
| User | NT AUTHORITY\SYSTEM |
| SHA1 | `A5BAD2CDD4BAEDB590A3646F7248BF060A2F13` |
| MD5 | `31890A7DE89936F922D44D677F681A7C` |
| SHA256 | `70C4C725E266F12ABAC850FD1598D4001201BCA8E7ACA901508307E365AFFF42` |
| IMPHASH | `A59258B3BCAE410F6DBF53F9767` |
| psexec artifacts | uploaded `DmmYUPVU.exe`, service `Wlug` (impacket random names) |

## Event IDs observed

| Event ID | Source | Meaning |
|---|---|---|
| **4720** | Security (Microsoft-Windows-Security-Auditing) | User account created (svc_backup) |
| **4732** | Security | Member added to Administrators group (svc_backup) |
| **1** | Microsoft-Windows-Sysmon/Operational | net.exe process creation ×2 (full command lines + hashes) |
| 4726 (if cleanup logged) | Security | Account deleted |

## ATT&CK mapping

- T1136.001 — Create Account: Local Account
- T1098.007 — Account Manipulation: Add Additional Local or Domain Groups (Sysmon ruleName tag)
- T1078 — Valid Accounts (backdoor account used for access)
- T1036 — Masquerading (service-account name/comment)
- T1059.003 — Windows Command Shell (net.exe via cmd)

## SIEM queries (DQL, verified)

```
data.win.system.eventID: 4720
data.win.system.eventID: 4732 and data.win.eventdata.targetUserName: "Administrators"
data.win.system.eventID: 1 and data.win.eventdata.image: "*net.exe*"
data.win.eventdata.targetUserName: "svc_backup" or data.win.eventdata.memberSid: "*1011"
```

## Behavioral signature

`net user <svc_*> /add /expires:never` (32-bit, from psexec cmd, as SYSTEM) → 4720 with machine-account subject → within hours `net localgroup Administrators <same> /add` → 4732 adding the same SID (correlate -1011) → `netexec` login as that account succeeds. Masqueraded service-account name + never-expires + immediate admin add + SYSTEM creator = backdoor.
