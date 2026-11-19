# 07 — Analysis

## What happened

Post-execution persistence: attacker used `impacket-psexec` (adminlab) to get SYSTEM, then created `svc_backup` — a backdoor account masquerading as a backup service account, set to never expire — and added it to the local Administrators group. Verified functional via `netexec` (`Pwn3d!`). This account survives reboots, password resets of the original admin, and removal of the initial foothold — it's the most durable persistence technique in Week 1.

## What each detection layer caught

| Layer | Event | Caught | Strength |
|---|---|---|---|
| Security audit (4720) | Account created | Account name, SID, creator (SYSTEM/machine), expiry | Best evidence; on by default |
| Security audit (4732) | Added to Administrators | Member SID (= -1011, correlates to 4720), group SID (S-1-5-32-544) | Correlation proves backdoor |
| Sysmon Event ID 1 | net.exe process | Full command lines (both), hashes, parent (psexec cmd), T1098.007 tag | Requires Sysmon |

## Evasion techniques observed

1. **Masquerading (T1036):** name `svc_backup`, full name "Backup Service Account", comment "Service account for automated backup" — looks legitimate at a glance.
2. **Never-expiring account (`/expires:never`):** ensures long-term persistence; many orgs don't audit account-expiry settings.
3. **Created from SYSTEM context:** 4720/4732 subject = machine account (`DESKTOP-F0JVTQT$`), not a user — blends into machine activity; a casual reviewer may dismiss it.
4. **32-bit net.exe (SysWOW64):** minor evasion; some defenders monitor only 64-bit paths.
5. **Two-session split:** account created Oct 30, added to admins Oct 31 — slows simple "same-minute" correlation rules (but SID correlation still works).

## Findings

1. **Backdoor account confirmed functional** — `netexec (Pwn3d!)` proves it; highest-severity persistence in Week 1.
2. **Creator = SYSTEM/machine account** (subject S-1-5-18) — anomalous; legitimate account creation is by a human admin. Finding.
3. **SID correlation (-1011)** between 4720 and 4732 is the key detection — a new account immediately (within a day) added to Administrators = backdoor.
4. **32 total 4720/4732 events** in Security log (includes earlier test accounts) — baseline noise; hunting requires filtering by new/unknown SIDs.
5. **Time offset persists** (Windows local vs Sysmon UTC) — NTP still needed.
6. **No high-severity built-in alert** on the 4720→4732 sequence — custom correlation rule needed (09).

## False-positive check

Legitimate service accounts exist (backup, monitoring), but: created by **SYSTEM/machine context**, **never expires**, **immediately added to Administrators**, named `svc_backup` on a **workgroup home machine** with no backup software, and **verified used for SMB admin login** from an external IP. Not a false positive.
