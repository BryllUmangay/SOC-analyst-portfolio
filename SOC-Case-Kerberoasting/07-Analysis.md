# 07 — Analysis

## What happened

Attacker with low-privilege `jdoe` enumerated SPNs (LDAP), requested a TGS for `svc_sql` (RC4 etype 23), took it offline, and cracked `svc_sql`'s password (`Password123`) in ~1 second. No admin rights needed, no interactive logon, no malware on the DC — the attack is stateless and nearly silent. The only footprint: two Kerberos events (4768 + 4769) on the DC.

## Why RC4 (0x17) is the smoking gun

- Modern Windows (AES configured) issues TGS tickets with **AES-256 (0x12)** or **AES-128 (0x11)**.
- **RC4-HMAC (0x17)** tickets are encrypted with the service account's **NTLM hash** — directly crackable offline (hashcat mode 13100).
- A service account that only supports RC4 is, by definition, roastable. Seeing 4769 with `ticketEncryptionType: 0x17` from an unmanaged/external client = high-confidence kerberoasting indicator.
- Even worse here: the **4768 TGT also used RC4 (0x17)** — AES not enforced domain-wide.

## Evasion / stealth properties

1. **No code execution on target** — pure Kerberos protocol abuse; nothing touches endpoints.
2. **Any valid domain user** can do this — no admin, no special rights.
3. **Offline cracking** — after the TGS is captured, no further DC contact; cracking rate is invisible to defenders.
4. **Blends in** — 4769 events fire constantly (every service access). Only the **RC4 encryption type + client IP + SPN pattern** stands out.
5. **Stateless** — no artifacts to clean up.

## Findings

1. **High — `svc_sql` password cracked** (`Password123`) via kerberoasting; service account compromised.
2. **Medium — RC4 (0x17) in use** for both TGT and TGS — AES not enforced; all RC4 SPN accounts are roastable.
3. **Medium — No high-severity alert** on 4769 RC4; built-in Wazuh rules miss it. Custom rule needed (09).
4. **Medium — DC clock skew** (~3 days behind real date) caused `KRB_AP_ERR_SKEW`; time infra needs fixing (DC as authoritative NTP).
5. **Low — SPN host label mismatch** (`DC01` vs real `WIN-BPME02TD5L2`) — not a vulnerability, but shows SPNs need inventory/cleanup.
6. **Low — Attacker IP .107** (DHCP) vs assumed .106 — always use observed IP.

## False-positive check

Legitimate 4769 events are constant. This one is suspicious because: **RC4 0x17** (modern = AES), client IP `.107` is an unmanaged Kali machine (not a domain workstation), single client requesting TGS for a **user-account SPN** (computer accounts auto-rotate, unbreakable; user SPNs = weak passwords), and `svc_sql` had a 10-char weak password. Not a false positive.
