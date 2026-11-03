# 01 — Scenario

## Background

An attacker has compromised a low-privilege domain user (`jdoe`) — e.g. via phishing or password spray. With **any valid domain credential**, they can request Kerberos Ticket-Granting Service (TGS) tickets for accounts with a Service Principal Name (SPN). The TGS is encrypted with the service account's NTLM hash. If the service account uses **RC4 encryption (etype 23)**, the attacker can take the TGS offline and crack it — no further interaction with the DC, no logon, nearly silent. This is **Kerberoasting (T1558.003)**.

## AD setup (pre-lab, on DC `192.168.100.105`)

- Domain: **BRYLL.LOCAL** (bryll.local). DC hostname: `WIN-BPME02TD5L2` (Wazuh agent `Windows-server`, agent.id 003).
- Audit policy: `Kerberos Service Ticket Operations` = **Success** (else 4769 won't log).
- Accounts: `jdoe` (regular user, `P@ssw0rd`), `svc_sql` (service account, weak password `Password123`).
- SPN registered: `setspn -A MSSQLSvc/DC01.bryll.local:1433 svc_sql` → `setspn -L svc_sql` confirms. (Host part `DC01` is a label; real DC hostname is `WIN-BPME02TD5L2` — any SPN registered to a user account is roastable.)
- Kali: DNS → DC, `/etc/hosts` entry, time sync required (DC clock behind real date).

## Snapshot before attack: DC + Win10 Pro clean baseline.

## Evidence for this stage
- `evidence/00-preflight-check.png`, `00-preflight-check1.png`, `00-preflight-check2.png` — audit policy, account creation, SPN registration.
