# 07 — Analysis
## What happened
An attacker with a low-priv domain user (`jdoe`) enumerated accounts exempt from Kerberos pre-authentication, found `svc_file` (UAC `0x410200`), requested its AS-REP with no pre-auth, and cracked its weak password (`Password123`) offline in ~39 seconds. No admin rights, no interactive logon, no malware, no logon failures — the only footprint is a single Audit-Success 4768 on the DC with `preAuthType=0`.

## Why preAuthType=0 is the smoking gun
- Normal AS exchange: client sends AS-REQ containing an **encrypted timestamp** (preAuthType=2) → DC verifies the client knows the key → issues TGT.
- With `DONT_REQUIRE_PREAUTH` (UAC 0x400000): DC **skips** that check and immediately returns the AS-REP, whose encrypted part is sealed with the account's NTLM key (RC4, etype 23). The attacker takes that blob offline and brute-forces the password.
- A 4768 with `preAuthType=0` for a **user account** is essentially never legitimate (only legacy appliances use it). It is the single highest-fidelity detector for this technique.

## AS-REP Roasting vs Kerberoasting (Week 2 Case 1)
| Dimension | Kerberoasting (T1558.003) | AS-REP Roasting (T1558.004, this case) |
|---|---|---|
| Trigger event | **4769** (TGS request) | **4768** (TGT/AS request) |
| Smoking-gun field | `ticketEncryptionType=0x17` (RC4 TGS) | **`preAuthType=0`** (+ RC4 0x17) |
| `targetUserName` in event | the **requesting user** (jdoe) | the **roasted account** (svc_file) |
| `serviceName` in event | the SPN account (svc_sql) | always `krbtgt` |
| Account requirement | target must have an **SPN** | target must have **DONT_REQUIRE_PREAUTH** (no SPN needed) |
| Hash format | `$krb5tgs$23$` (hashcat 13100) | `$krb5asrep$23$` (hashcat **18200**) |
| Valid domain creds needed? | Yes (to request TGS) | No* (roast itself is unauthenticated; creds only for enumeration) |

\* GetNPUsers can roast with no creds at all if you know/guess the account name; the `-request` AS-REQ for `svc_file` is anonymous.

## Evasion / stealth properties
1. **Zero logon failures** — the AS-REQ succeeds (status 0x0); no 4625, no account lockout. Brute-force detection never sees it.
2. **Offline cracking** — after the AS-REP is captured, no further DC contact; cracking speed (325 kH/s) is invisible to defenders.
3. **Blends into 4768 noise** — TGT requests fire constantly. Only `preAuthType=0` (and RC4 0x17) stands out. Default Wazuh alerting misses both.
4. **Stateless** — no artifacts, no persistence, no cleanup.
5. **Any account, not just SPN accounts** — unlike kerberoasting, a plain user with the pre-auth exemption bit is roastable; no SPN inventory required.

## Findings
1. **High — `svc_file` credential compromised** (`Password123` cracked via AS-REP roast). Valid domain credential in attacker hands.
2. **High — `DONT_REQUIRE_PREAUTH` present** on a user account (UAC 0x400000) — the root cause; must be removed domain-wide.
3. **Medium — RC4 (0x17) in use** for the AS-REP — AES not enforced; RC4 is what makes the captured blob crackable.
4. **Medium — No default alert** on 4768 preAuthType=0; built-in Wazuh rules log it at low severity. Custom rule required (09).
5. **Low — Time infra** — Kali was ~3 min fast (ntpdate -180 s); DC as authoritative NTP would prevent skew issues. 13 h tz display offset (Kali EST vs Wazuh PHT) documented.
6. **Low — Attacker IP .107** (DHCP) vs earlier .106 — always use observed IP from logs.
7. **Informational — `svc_file` never logged on interactively** (LastLogon `<never>`); cracking was the final step in this lab, so no post-crack lateral movement to hunt.

## False-positive check
Legitimate preAuthType=0 is extremely rare and limited to legacy Unix/embedded appliances explicitly configured for it. For a regular user account (`svc_file`, PasswordNeverExpires, weak password) requesting from an unmanaged IP (`.107`, Kali), this is **not** a false positive. Filter known exempt appliance accounts in the detection rule; alert on everything else.
