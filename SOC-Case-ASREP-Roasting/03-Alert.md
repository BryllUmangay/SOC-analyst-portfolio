# 03 — Alert / Detection (actual events)
Agent `Windows-server` (DC, 192.168.100.105, agent.id 003). Index `wazuh-archives-*`. DQL query: `data.win.system.eventID: 4768` → **20 hits** (last 24 h).
📸 `evidence/04-wazuh-4768-list.png`

## 1. Event ID 4768 — TGT requested with NO pre-authentication (the money shot)
Expanded event (eventRecordID **8654**), index `wazuh-archives-4.x-2026.11.04`:
📸 `evidence/05-wazuh-4768-expanded-preauth0.png`

| Field | Value |
|---|---|
| `eventID` | **4768** — "A Kerberos authentication ticket (TGT) was requested." |
| `targetUserName` / `targetSid` | **svc_file** / `S-1-5-21-1845810679-4027539410-2363447484-1603` (RID 1603 — matches AD SID exactly) |
| `targetDomainName` | BRYLL.LOCAL |
| `serviceName` / `serviceSid` | **krbtgt** / `S-1-5-21-1845810679-4027539410-2363447484-502` |
| `ipAddress` / `ipPort` | **`::ffff:192.168.100.107`** / **34658** (Kali attacker) |
| **`preAuthType`** | **`0`** — **NO pre-authentication — SMOKING GUN** (normal users = `2`, encrypted timestamp) |
| **`ticketEncryptionType`** | **`0x17`** — RC4-HMAC (etype 23) — the AS-REP part is crackable offline |
| `ticketOptions` / `status` | `0x50800000` / `0x0` (success) |
| `channel` / `computer` | Security / `WIN-BPME02TD5L2.bryll.local` |
| `keywords` | `0x8020000000000000` (Audit Success) |

**Why preAuthType=0 is the smoking gun:** in normal Kerberos, the AS-REQ includes an encrypted timestamp (preAuthType=2) so the DC can verify the user knows the key before issuing a TGT. With `DONT_REQUIRE_PREAUTH`, the DC skips that check and returns the encrypted AS-REP part immediately — that encrypted blob is what the attacker cracks. A 4768 with `preAuthType=0` for a user account is, by itself, a high-fidelity AS-REP roasting indicator.

## 2. Baseline (normal) 4768 — for comparison
From the same 20-hit list: `DESKTOP-B5RJ6HF6$` (domain-joined Win10 Pro) @ `Nov 4 22:35:23.552` with `ticketOptions: 0x40810010` — a standard pre-authenticated TGT request (preAuthType=2). Only the `svc_file` row carries `ticketOptions 0x50800000` + preAuthType=0. This contrast is what a hunting query isolates.

## Detection gap note
Built-in Wazuh rules log 4768 at low/informational severity and do **not** inspect `preAuthType` — a single successful AS-REP roast generates only an Audit-Success 4768 and zero logon failures, so it is invisible to default alerting. Custom rule targeting `preAuthType=0` is required (see `09-Remediation.md`).
