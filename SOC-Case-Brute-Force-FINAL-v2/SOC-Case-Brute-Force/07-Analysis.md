# 07 — Analysis

## What happened

An attacker at `192.168.100.107` performed an SMB password-guessing attack (T1110.001) against the Windows 10 Home workstation `winhome01` (`192.168.100.108`). Over several minutes the attacker attempted credential pairs against TCP/445. **Hydra was tried first and failed** — SMBv1 is disabled on Windows 10 Home and Hydra's SMB module could not negotiate the modern dialect, so it returned zero valid pairs and generated no 4625 telemetry. The attacker switched to **NetExec**, which produced **41 failed logons (4625)**, **two successful logons (4624 type 3)** — `jdoe:Password1` (first compromise) then `adminlab:P@ssw0rd` (local admin, `(Pwn3d!)`) — and **one account lockout (4740)** on `mreyes`. The attack targeted local accounts (`jdoe`, `mreyes`, `adminlab`, `administrator`, `guest`).

## Why the telemetry looks the way it does

- **Event ID 4625** — every failed NTLM logon over SMB. `Logon Type = 3` (network logon) confirms the attempts came over the network, not interactively at the console.
- **SubStatus `0xC000006A`** = wrong password for a valid user (the bulk); `0xC0000064` = user doesn't exist (`guest`/`administrator` on Home); `0xC0000234` = account locked out.
- **Event ID 4740** — account lockout threshold (5 failures) triggered on the non-admin accounts; `adminlab` may have been reached before lockout (or lockout policy excludes admins — verify).
- **Event ID 4624 (type 3)** — the successful logon. Its position *immediately after* the failure burst is what distinguishes a successful brute force from a failed one.

## Brute force vs password spray (compare with Week-1 case #2)

| | Brute force (this case) | Password spray |
|---|---|---|
| Pattern | Many passwords, few accounts | One/common password, many accounts |
| 4625 distribution | Concentrated on 1–3 usernames | Spread across many usernames |
| Lockout risk | High (locks the targeted accounts) | Low (one attempt per account) |
| Detection | Burst + lockout (4740) + eventual 4624 | Low-and-slow 4625 across accounts |

## Attacker IP note

The source IP `192.168.100.107` appears in every 4625's `IpAddress` field. In a real incident this would be the pivot for blocking and threat-intel lookup. In this lab it's the Kali machine — document that the Wazuh agent on the victim correctly captured the true source.

## Tooling note — Hydra failed, NetExec succeeded
The first attack tool (Hydra, `smb://`) returned zero valid pairs and generated **no 4625 telemetry at all** because SMBv1 is disabled on the target and Hydra's SMB module could not negotiate the modern dialect. The attacker switched to NetExec and successfully guessed two credentials.
- **Defender lesson:** a target that "survives" one brute-force tool may still be brute-forceable — attackers pivot tools. Absence of 4625 telemetry does **not** prove an attack was blocked; it may mean the tool never reached the authentication stage.
- **Analyst lesson:** if a suspected brute-force window shows zero 4625s, check protocol-layer logs (SMB negotiation failures, TCP resets) before closing the alert — the attack may have used a tool that failed pre-auth.

## False-positive considerations

- A single 4625 = user typo. Not an incident.
- Repeated 4625 from a known IT admin machine = possibly a stale mapped drive / scheduled task with old creds. Check `4648` and credential manager before escalating.
- The deciding factor here: **source IP is unknown + burst + successful logon**.
